/*
 * ssr.c - Software RAID
 *
 * Author: Andrei Botila <andreibotila95@gmail.com>
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/genhd.h>
#include <linux/blkdev.h>
#include <linux/crc32.h>

#include "ssr.h"

struct ssr_work {
	struct work_struct work;
	struct bio *ssr_bio;
};

struct ssr_device {
	struct block_device *vdb, *vdc;
	struct request_queue *queue;
	struct gendisk *gd;
} ssr_dev;

static int ssr_open(struct block_device *bdev, fmode_t mode)
{
	return 0;
}

static void ssr_release(struct gendisk *gd, fmode_t mode)
{
}

static const struct block_device_operations ssr_ops = {
	.owner		=	THIS_MODULE,
	.open		=	ssr_open,
	.release	=	ssr_release
};

/* Reading the necessary crc sectors for the specific data sectors
 * from the specific virtual device.
 */
static void read_crc_bio(struct bio_vec *bvec, struct bvec_iter *iter,
	struct block_device *vd, unsigned long *read_crc)
{
	struct bio *bio_vd_crc;
	struct page *vd_page_crc;
	unsigned long *vd_crc;
	sector_t crc_sector;

	/* Alloc page for vdX */
	bio_vd_crc = bio_alloc(GFP_NOIO, 1);
	vd_page_crc = alloc_page(GFP_NOIO);

	/* We calculate logical disk sector in which crc resides */
	crc_sector = iter->bi_sector / CRC_SECTORS_SECTOR;

	bio_vd_crc->bi_disk = vd->bd_disk;
	/* Adding LOGICAL_DISK_SECTORS for passing the data sectors */
	bio_vd_crc->bi_iter.bi_sector = crc_sector + LOGICAL_DISK_SECTORS;
	bio_set_op_attrs(bio_vd_crc, REQ_OP_READ, 0);
	bio_add_page(bio_vd_crc, vd_page_crc, PAGE_SIZE, 0);
	submit_bio_wait(bio_vd_crc);

	vd_crc = kmap_atomic(vd_page_crc);
	memcpy(read_crc, vd_crc, PAGE_SIZE);
	kunmap_atomic(vd_crc);

	bio_put(bio_vd_crc);
	__free_page(vd_page_crc);
}

/* Reading the necessary data sectors from the specific virtual device. */
static void read_data_bio(struct bio_vec *bvec, struct bvec_iter *iter,
	struct block_device *vd, char *read_data)
{
	struct bio *bio_vd;
	struct page *vd_page;
	char *bio_buf;
	char *vd_buf;

	/* Alloc bio and page for vdX */
	bio_vd = bio_alloc(GFP_NOIO, 1);
	vd_page = alloc_page(GFP_NOIO);

	bio_vd->bi_disk = vd->bd_disk;
	bio_vd->bi_iter.bi_sector = iter->bi_sector;
	bio_set_op_attrs(bio_vd, REQ_OP_READ, 0);
	bio_add_page(bio_vd, vd_page, PAGE_SIZE, 0);
	submit_bio_wait(bio_vd);

	/* Savind the read data from the finished bio. */
	vd_buf = kmap_atomic(vd_page);
	bio_buf = kmap_atomic(bvec->bv_page);

	memcpy(read_data, vd_buf, PAGE_SIZE);
	memcpy(bio_buf, read_data, PAGE_SIZE);

	kunmap_atomic(bio_buf);
	kunmap_atomic(vd_buf);

	bio_put(bio_vd);
	__free_page(vd_page);
}

/* Writing the crc sectors for the received data sectors
 * on the specific virtual device.
 */
static void write_crc_bio(struct bio_vec *bvec, struct bvec_iter *iter,
	struct block_device *vd)
{
	struct bio *bio_vd_crc;
	struct page *vd_page_crc;
	char *rcv_buf;
	unsigned long *vd_crc, *cur_crc;
	unsigned long sector_crc32;
	unsigned long pos_crc;
	sector_t crc_sector;
	unsigned int i;

	/* Read already calculated CRCs for the specific page.
	 * Get all the 128 * 8 CRCs and modify only the necessary ones.
	 */
	cur_crc = kzalloc(PAGE_SIZE, GFP_KERNEL);
	read_crc_bio(bvec, iter, vd, cur_crc);

	/* Alloc bio and page for /dev/vdX */
	bio_vd_crc = bio_alloc(GFP_NOIO, 1);
	vd_page_crc = alloc_page(GFP_NOIO);

	/* Map page for reading the data and computing crc
	 * for the specific crc sector in /dev/vdX.
	 */
	rcv_buf = kmap_atomic(bvec->bv_page);
	vd_crc = kmap_atomic(vd_page_crc);
	memcpy(vd_crc, cur_crc, PAGE_SIZE);

	/* We calculate logical disk sector
	 * in which CRC for this data sector resides.
	 */
	crc_sector = iter->bi_sector / CRC_SECTORS_SECTOR;

	/* Compute CRC for each sector and copy it to specific sector. */
	for (i = 0; i < (iter->bi_size / KERNEL_SECTOR_SIZE); i++) {
		sector_crc32 = crc32(0, rcv_buf + (i * KERNEL_SECTOR_SIZE),
					KERNEL_SECTOR_SIZE);

		/* CRC sector inside disk sectors */
		pos_crc = (iter->bi_sector % CRC_SECTORS_SECTOR) + i;
		memcpy(vd_crc + pos_crc, &sector_crc32,
			CRC_SIZE);
	}

	kunmap_atomic(vd_crc);
	kunmap_atomic(rcv_buf);

	bio_vd_crc->bi_disk = vd->bd_disk;
	/* Adding LOGICAL_DISK_SECTORS for passing the data sectors */
	bio_vd_crc->bi_iter.bi_sector = crc_sector + LOGICAL_DISK_SECTORS;
	bio_set_op_attrs(bio_vd_crc, REQ_OP_WRITE, 0);
	bio_add_page(bio_vd_crc, vd_page_crc, PAGE_SIZE, 0);
	submit_bio_wait(bio_vd_crc);

	bio_put(bio_vd_crc);
	__free_page(vd_page_crc);
	kfree(cur_crc);
}

/* Writing the data sectors received on the specific virtual device. */
static void write_data_bio(struct bio_vec *bvec, struct bvec_iter *iter,
	struct block_device *vd)
{
	struct bio *bio_vd_data;
	struct page *vd_page_data;
	char *rcv_buf, *send_buf;
	char *vd_buf;

	/* Alloc bio and page for /dev/vdX */
	bio_vd_data = bio_alloc(GFP_NOIO, 1);
	vd_page_data = alloc_page(GFP_NOIO);

	send_buf = kzalloc(PAGE_SIZE, GFP_KERNEL);
	/* Map page for reading the data and writing it
	 * to specific sector in /dev/vdX.
	 */
	rcv_buf = kmap_atomic(bvec->bv_page);
	vd_buf = kmap_atomic(vd_page_data);

	memcpy(send_buf, rcv_buf, PAGE_SIZE);
	memcpy(vd_buf, send_buf, PAGE_SIZE);

	kunmap_atomic(vd_buf);
	kunmap_atomic(rcv_buf);

	/* /dev/vdX data */
	bio_vd_data->bi_disk = vd->bd_disk;
	bio_vd_data->bi_iter.bi_sector = iter->bi_sector;
	bio_set_op_attrs(bio_vd_data, REQ_OP_WRITE, 0);
	bio_add_page(bio_vd_data, vd_page_data, PAGE_SIZE, 0);
	submit_bio_wait(bio_vd_data);

	bio_put(bio_vd_data);
	__free_page(vd_page_data);
	kfree(send_buf);
}

static void ssr_work_handler(struct work_struct *work)
{
	struct ssr_work *ssr_work;
	struct bio *ssr_bio;
	struct bio_vec bvec;
	struct bvec_iter iter;
	unsigned long *read_crc_vdb, *read_crc_vdc;
	unsigned long crc_vdb, crc_vdc;
	unsigned long crc_vdb_comp, crc_vdc_comp;
	unsigned long crc_pos, crc_sector;
	unsigned int i, err;
	char *read_data_vdb, *read_data_vdc;
	char *bio_buf;

	err = 0;
	/* Get specific bio and device from the work structure. */
	ssr_work = container_of(work, struct ssr_work, work);
	ssr_bio = ssr_work->ssr_bio;

	if (bio_data_dir(ssr_bio) == REQ_OP_WRITE) {
		bio_for_each_segment(bvec, ssr_bio, iter) {
			/* Write data and crc for the first device.*/
			write_data_bio(&bvec, &iter, ssr_dev.vdb);
			write_crc_bio(&bvec, &iter, ssr_dev.vdb);

			/* Write data and crc for the second device. */
			write_data_bio(&bvec, &iter, ssr_dev.vdc);
			write_crc_bio(&bvec, &iter, ssr_dev.vdc);
		}
	}
	if (bio_data_dir(ssr_bio) == REQ_OP_READ) {
		bio_for_each_segment(bvec, ssr_bio, iter) {
			/* Calculating disk sector and crc sector inside disk. */
			crc_sector = iter.bi_sector / CRC_SECTORS_SECTOR;
			crc_pos =  iter.bi_sector % CRC_SECTORS_SECTOR;

			/* Reading data and crc from /dev/vdb
			 * for the checks regarding the data integrity.
			 */
			read_data_vdb = kzalloc(PAGE_SIZE, GFP_KERNEL);
			read_crc_vdb = kzalloc(PAGE_SIZE, GFP_KERNEL);
			read_data_bio(&bvec, &iter, ssr_dev.vdb, read_data_vdb);
			read_crc_bio(&bvec, &iter, ssr_dev.vdb, read_crc_vdb);

			/* Reading data and crc from /dev/vdc
			 * for the checks regarding the data integrity.
			 */
			read_data_vdc = kzalloc(PAGE_SIZE, GFP_KERNEL);
			read_crc_vdc = kzalloc(PAGE_SIZE, GFP_KERNEL);
			read_data_bio(&bvec, &iter, ssr_dev.vdc, read_data_vdc);
			read_crc_bio(&bvec, &iter, ssr_dev.vdc, read_crc_vdc);

			for (i = 0; i < (PAGE_SIZE / KERNEL_SECTOR_SIZE); i++) {
				/* Computing the crc value for the specific
				 * sectors that should be read.
				 */
				crc_vdb_comp = crc32(0, read_data_vdb + (i * KERNEL_SECTOR_SIZE),
						KERNEL_SECTOR_SIZE);
				crc_vdc_comp = crc32(0, read_data_vdc + (i * KERNEL_SECTOR_SIZE),
						KERNEL_SECTOR_SIZE);

				/* Get the actual crc value for the sector from the disk.*/
				memcpy(&crc_vdb, read_crc_vdb + crc_pos + i, CRC_SIZE);
				memcpy(&crc_vdc, read_crc_vdc + crc_pos + i, CRC_SIZE);

				/* Both disk have corrupted crc values. */
				if (crc_vdb != crc_vdb_comp && crc_vdc != crc_vdc_comp) {
					err = 1;
					goto out_error;
				}

				/* /dev/vdc has correct crc value. */
				if (crc_vdb != crc_vdb_comp) {
					/* Get the correct sector data from /dev/vdc. */
					bio_buf = kmap_atomic(bvec.bv_page);
					memcpy(bio_buf + (i * KERNEL_SECTOR_SIZE),
						read_data_vdc + (i * KERNEL_SECTOR_SIZE), KERNEL_SECTOR_SIZE);
					kunmap_atomic(bio_buf);

					/* Write the correct data and compute the new crc value. */
					write_data_bio(&bvec, &iter, ssr_dev.vdb);
					write_crc_bio(&bvec, &iter, ssr_dev.vdb);
				}

				/* /dev/vdb has correct crc value. */
				if (crc_vdc != crc_vdc_comp) {
					/* Get the correct sector data from /dev/vdb. */
					bio_buf = kmap_atomic(bvec.bv_page);
					memcpy(bio_buf + (i * KERNEL_SECTOR_SIZE),
						read_data_vdb + (i * KERNEL_SECTOR_SIZE), KERNEL_SECTOR_SIZE);
					kunmap_atomic(bio_buf);

					/* Write the correct data and compute the new crc value. */
					write_data_bio(&bvec, &iter, ssr_dev.vdc);
					write_crc_bio(&bvec, &iter, ssr_dev.vdc);
				}
			}

			kfree(read_crc_vdc);
			kfree(read_data_vdc);
			kfree(read_crc_vdb);
			kfree(read_data_vdb);
		}
	}

	bio_endio(ssr_bio);
out_error:
	if (err) {
		kfree(read_crc_vdc);
		kfree(read_data_vdc);
		kfree(read_crc_vdb);
		kfree(read_data_vdb);
		bio_io_error(ssr_bio);
	}
}

static blk_qc_t ssr_make_request(struct request_queue *q, struct bio *bio)
{
	struct ssr_work *ssr_work_vdb;

	/* Generate work for /dev/vdb and queue it. */
	ssr_work_vdb = kmalloc(sizeof(struct ssr_work), GFP_ATOMIC);
	ssr_work_vdb->ssr_bio = bio;
	INIT_WORK(&ssr_work_vdb->work, ssr_work_handler);
	schedule_work(&ssr_work_vdb->work);

	return BLK_QC_T_NONE;
}

static int create_block_device(struct ssr_device *dev)
{
	int err;

	/* First physical device, /dev/vdb. */
	dev->vdb = blkdev_get_by_path(PHYSICAL_DISK1_NAME,
			FMODE_READ | FMODE_WRITE | FMODE_EXCL, THIS_MODULE);
	if (IS_ERR(dev->vdb)) {
		pr_err("blkdev_get_by_path vdb: failure");
		err = -EINVAL;
		goto out_blkdev_get_vdb;
	}

	/* Second physical device, /dev/vdc. */
	dev->vdc = blkdev_get_by_path(PHYSICAL_DISK2_NAME,
			FMODE_READ | FMODE_WRITE | FMODE_EXCL, THIS_MODULE);
	if (IS_ERR(dev->vdc)) {
		pr_err("blkdev_get_by_path vdc: failure");
		err = -EINVAL;
		goto out_blkdev_get_vdc;
	}

	/* Although initialized it is not used since we process
	 * at structure bio level. This way requests are not reordered.
	 */
	dev->queue = blk_alloc_queue(GFP_KERNEL);
	if (dev->queue == NULL) {
		pr_err("blk_alloc_queue: failure");
		err = -ENOMEM;
		goto out_blk_alloc_queue;
	}
	blk_queue_make_request(dev->queue, ssr_make_request);
	dev->queue->queuedata = dev;

	dev->gd = alloc_disk(SSR_NUM_MINORS);
	if (!dev->gd) {
		pr_err("alloc_disk: failure");
		err = -ENOMEM;
		goto out_alloc_disk;
	}

	dev->gd->major = SSR_MAJOR;
	dev->gd->first_minor = SSR_FIRST_MINOR;
	dev->gd->fops = &ssr_ops;
	dev->gd->queue = dev->queue;
	dev->gd->private_data = dev;
	snprintf(dev->gd->disk_name, DISK_NAME_LEN, "ssr");
	set_capacity(dev->gd, LOGICAL_DISK_SECTORS);

	add_disk(dev->gd);

	return 0;

out_alloc_disk:
	blk_cleanup_queue(dev->queue);
out_blk_alloc_queue:
	blkdev_put(dev->vdc, FMODE_READ | FMODE_WRITE | FMODE_EXCL);
out_blkdev_get_vdc:
	blkdev_put(dev->vdb, FMODE_READ | FMODE_WRITE | FMODE_EXCL);
out_blkdev_get_vdb:
	return err;
}

static int ssr_init(void)
{
	int err;

	err = register_blkdev(SSR_MAJOR, LOGICAL_DISK_NAME);
	if (err < 0) {
		pr_err("Unable to register ssr block device");
		goto out_register;
	}

	err = create_block_device(&ssr_dev);
	if (err < 0) {
		pr_err("Unable to create block device");
		goto out_create;
	}

	return 0;

out_create:
	unregister_blkdev(SSR_MAJOR, LOGICAL_DISK_NAME);
out_register:
	return err;
}

static void delete_block_device(struct ssr_device *dev)
{
	if (dev->gd) {
		del_gendisk(dev->gd);
		put_disk(dev->gd);
	}

	if (dev->queue)
		blk_cleanup_queue(dev->queue);

	if (dev->vdb)
		blkdev_put(dev->vdb, FMODE_READ | FMODE_WRITE | FMODE_EXCL);

	if (dev->vdc)
		blkdev_put(dev->vdc, FMODE_READ | FMODE_WRITE | FMODE_EXCL);
}

static void ssr_exit(void)
{
	delete_block_device(&ssr_dev);
	unregister_blkdev(SSR_MAJOR, LOGICAL_DISK_NAME);
}

module_init(ssr_init);
module_exit(ssr_exit);

MODULE_DESCRIPTION("Driver for Software RAID");
MODULE_AUTHOR("Andrei Botila <andreibotila95@gmail.com>");
MODULE_LICENSE("GPL v2");

