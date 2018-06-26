#define _LARGEFILE64_SOURCE
 
#include <errno.h>
#include <sys/types.h>
#include <poll.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/mman.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <unistd.h>
#include <time.h>

#include "target_core_ofs.h"
#include "scsi.h"


#define PAGE_SIZE 4096
#define ROUND_UP_PAGES(a) ((a + PAGE_SIZE - 1) / PAGE_SIZE)

static int dev_fd, signal_fd;

/*
struct mailbox{
	u16  stjb_codef;		//offset 00
	s16  stjb_status;		//offset 02
	u16  stjb_ticuser_root;	//offset 04
	u8   stjb_piduser[4];	//offset 06
	u16  stjb_mode;			//offset 0A
	u16  stjb_time;			//offset 0C
	u16  stjb_stop;			//offset 0E
	u16  stjb_nfonc;		//offset 10
	u16  stjb_ncard;		//offset 12
	u16  stjb_nchan;		//offset 14
	u16  stjb_nes;			//offset 16
	u16  stjb_nb;			//offset 18
	u16  stjb_typvar;		//offset 1A
	u32  stjb_adr;			//offset 1C
	u16  stjb_ticuser_dispcyc;	//offset 20
	u16  stjb_ticuser_protocol;	//offset 22
	u8   stjb_filler[12];		//offset 24
	u8   stjb_data[256];		//offset 30
	};
*/
static struct mailbox *mb;

static int block_size = 512;	//scsi数据块的最小长度是 512字节

#define print printf 
//#define print 

void getNowTime()
{
	struct tm *t;
	time_t tt;
	char current[1024];
	
	time(&tt);
	t = localtime(&tt);
	memset(current, 0, sizeof(current));
	sprintf(current, "UTC time :[%04d%02d%02d %02d:%02d:%02d]", t->tm_year + 1900, t->tm_mon+1, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec);
	printf("%s\n", current);
}

void printMem(unsigned char *data, unsigned int count)
{
	unsigned int i;
    for(i = 0; i < count;) {
    	printf("[%08d][%p][0x%x]|[%08d][%p][0x%x]|[%08d][%p][0x%x]|[%08d][%p][0x%x]\n", \
    	i, &data[i], data[i], i+1, &data[i+1], data[i+1], i+2, &data[i+2], data[i+2], i+3, &data[i+3], data[i+3]);
        i = i + 4;
    }
}

//功能: 根据scsi命令的第1个字节，可以判断命令的类型和长度, 返回scsi命令本身的长度
static inline int get_cdb_length(uint8_t *cdb)
{
	uint8_t opcode = cdb[0];

	// See spc-4 4.2.5.1 operation code
	//
	if (opcode <= 0x1f)
		return 6;
	else if (opcode <= 0x5f)	//WRITE_10: 0x2a  READ_10: 0x28 都是10字节命令
		return 10;
	else if (opcode >= 0x80 && opcode <= 0x9f)
		return 16;
	else if (opcode >= 0xa0 && opcode <= 0xbf)
		return 12;
	else
		return -1;
}

//功能: 获取cdb d lba值
uint64_t get_lba(uint8_t *cdb)
{
	uint8_t val6;

	switch (get_cdb_length(cdb)) {
	case 6:
		val6 = be16toh(*((uint16_t *)&cdb[2]));
		return val6 ? val6 : 256;
	case 10:	//10字节的 scsi 命令
		return be32toh(*((u_int32_t *)&cdb[2]));
		//be32toh(): 将网络字节序转化成主机字节序
		//将cdb[2]开始的4个字节(32位)转化成 主机字节序数据
	case 12:
		return be32toh(*((u_int32_t *)&cdb[2]));
	case 16:
		return be64toh(*((u_int64_t *)&cdb[2]));
	default:
		return -1;
	}
}

//功能: 
uint32_t get_length(uint8_t *cdb)
{
	switch (get_cdb_length(cdb)) {
	case 6:
		return cdb[4];
	case 10:	//10字节的 scsi 命令
		return be16toh(*((uint16_t *)&cdb[7]));
		//将cdb[7]开始的2个字节(16位)转化成 主机字节序数据
	case 12:
		return be32toh(*((u_int32_t *)&cdb[6]));
	case 16:
		return be32toh(*((u_int32_t *)&cdb[10]));
	default:
		return -1;
	}
}

/*
功能: 处理1次 TCMU 命令
mb: 邮箱的入口，即共享内存的入口
ent: TCMU 命令的入口
*/
int handle_one_command(struct mailbox *mb, struct ofs_cmd_entry *ent)
{
	uint8_t cmd;
	uint8_t *cdb;

	print("handling a command!\n");

	print("handling a command: &ent->hdr=[%p]\n", &ent->hdr);		//和 ent 地址128 相同
	print("handling a command: &ent->req = [%p]\n", &ent->req);		//&ent->req = &ent + 8 //req和rsp才是相同的地址， req和hdr地址相差 8字节
	print("handling a command: ent->req.cdb_off = [%d]\n", ent->req.cdb_off);		//0xf0=240: scsi 命令 相对于邮箱起始地址的偏移量，占8字节
	cdb = (void *)mb + ent->req.cdb_off;							//相对于邮箱的偏移地址
	print("handling a command: cdb = [%p]\n", cdb);					//0+240
	print("handling a command: &ent->req.iov_cnt = [%p]\n", &(ent->req.iov_cnt));	//&ent->req.iov_cnt = &ent + 8 + 8
	print("handling a command: ent->req.iov_cnt = [%d]\n", ent->req.iov_cnt);		//1	

	cmd = cdb[0];	//scsi命令的第1个字节，可以判断命令的类型和长度
	print("handling a command: cmd = [0x%x]\n", cmd);	//READ_10 0x28 //可以判断是10字节的scsi命令

	int i = 0;
	int remaining, ret = 0;
	struct iovec *iov;
	for(i = 0; i < 10; ++i) {
		print("[%x]", cdb[i]);
	}
	print("\n");
	/*
	cdb[0]=[28]		//scsi命令的操作码: 它定义了命令的类型和长度.所以，解码了这个字节之后，就知道这个命令后面还剩多少字节。
	cdb[1]=[0]
	cdb[2]=[0]		//LBA: (逻辑块起始地址的偏移值,高字节) 接口 get_lba(cdb) 解析这4个字节的数据, 是相对于 iov内存块的偏移值。
	cdb[3]=[0]		//LBA:
	cdb[4]=[0]		//LBA:
	cdb[5]=[0]		//LBA: (逻辑块起始地址的偏移值,低字节)
	cdb[6]=[0]		//保留字段
	cdb[7]=[0]		//length: (逻辑块的数量: 传输长度,高字节): 接口 get_length(cdb) 解析这2个字节的数据
	cdb[8]=[8]		//length: (逻辑块的数量: 传输长度,低字节): 
	cdb[9]=[0]		//控制字节,用于表示与供应商相关的信息等等。
	*/

	unsigned int data_bytes = block_size * cdb[8];	//当长度很小时，可以直接这样取值，长度很大时不对
	print("handling a command: data bytes = [%d]\n", data_bytes);

	//remaining = data_bytes;
	iov = &ent->req.iov[0];
	print("handling a command: iov addr_0 = [%p]\n", iov);		//&iov = &hdr + 8 + 8 + 8 = 152
	int iov_length = iov->iov_len;
	print("handling a command: iov->iov_len = [%d]\n", iov->iov_len);		//4K
	print("handling a command: iov->iov_base = [%x]\n", iov->iov_base);		//0x10000
	print("handling a command: (size_t)iov->iov_base = [%d]\n", (size_t)iov->iov_base);	//65536 = 0x10000 = 64k
	print("handling a command: iov->iov_base addr = [%p]\n", (unsigned char *)((void *)mb + (size_t)iov->iov_base));	//在邮箱地址+64k 地址处开始，长度为4k的地方存放数据
	//printMem((unsigned char *)((void *)mb + (size_t)iov->iov_base), (unsigned int)iov_length);

	//uint64_t lba = be32toh(*((u_int32_t *)&cdb[2])) * block_size;
	//uint64_t length = be16toh(*((uint16_t *)&cdb[7])) * block_size;

	print("handling a command: get_lba(cdb) = [%d]\n", get_lba(cdb));		//0 : cdb 逻辑块起始地址的偏移值
	print("handling a command: get_length(cdb) = [%d]\n", get_length(cdb));	//8 : cdb 逻辑块数量
	uint64_t lba = get_lba(cdb) * block_size;			//cdb 逻辑块偏移地址	//是相对于 iov内存块的偏移值。
	uint64_t length = get_length(cdb) * block_size;		//8*512 = 4k : cdb 逻辑块数据长度	
	remaining = length;									//4k 还未处理的数据长度	注意: 这个长度和 iov->iov_len 的值应该相等。
	print("handling a command: lba = [%lld]\n", lba);
	print("handling a command: remaining = [%lld]\n", remaining);

	uint64_t doneLength = 0;	//已经处理了的数据的长度

	switch(cmd)
	{
		case WRITE_6:		//0x0a
		case WRITE_10:		//0x2a
		case WRITE_12:		//0xaa
		case WRITE_16:		//0x8a
			//循环是确保指定长度写完整
			while(remaining) {
				//先设置文件写位置偏移位置(lba + doneLength), 再将共享内存起始地址 (void *)mb + (size_t)iov->iov_base 处，iov->iov_len 字节的数据，保存到文件指定的偏移地址中
				/*
				ret = pwrite64(dev_fd, (void *)mb + (size_t)iov->iov_base, iov->iov_len, lba + doneLength);
				if(ret != iov->iov_len) {
					ent->rsp.scsi_status = 2;
				}
				*/
				//通过虚拟磁盘传递真实备份数据之前，会先传递一些协议的数据
				print("WRITE handling a command: iov->iov_base addr = [%p]\n", (unsigned char *)((void *)mb + (size_t)iov->iov_base));
				print("WRITE handling a command: lba = [%lld]\n", lba);				
				print("WRITE handling a command: doneLength = [%d]\n", doneLength);
				print("WRITE handling a command: iov->iov_len = [%d]\n", iov->iov_len);
				//printMem((unsigned char *)((void *)mb + (size_t)iov->iov_base + lba + doneLength), (unsigned int)iov->iov_len);
				/*
				for(i=0; i<iov->iov_len; i++)
				{
					printf("buf[i]=[%c]\n", ((char*)((void *)mb + (size_t)iov->iov_base))[i]);
				}
				*/
				remaining -= iov->iov_len;
				print("WRITE handling a command: remaining = [%d]\n", remaining);
				doneLength += iov->iov_len;
				print("WRITE handling a command: doneLength = [%d]\n", doneLength);

				print("WRITE handling a command: iov addr_1 = [%p]\n", iov);
				iov++;
				print("WRITE handling a command: iov addr_2 = [%p]\n", iov);
			}
			ent->rsp.scsi_status = 0;
			break;
		case READ_6:		//0x08
		case READ_10:		//0x28
		case READ_12:		//0xa8
		case READ_16:		//0x88
			
			//循环是确保指定长度读取完整
			while(remaining) {
				print("READ handling a command: iov->iov_base addr = [%p]\n", (unsigned char *)((void *)mb + (size_t)iov->iov_base));	//mb+64k
				print("READ handling a command: lba = [%lld]\n", lba);					//0: cdb 逻辑块偏移地址	//是相对于 iov内存块的偏移值。
				print("READ handling a command: doneLength = [%d]\n", doneLength);
				print("READ handling a command: iov->iov_len = [%d]\n", iov->iov_len);	//4k
				
				//TODO: dev_fd 是本地卷的句柄，这里为什么是本地卷?
				//功能: 先设置 dev_fd 文件的 文件读偏移位置(lba + doneLength)处，从这个位置读取 iov->iov_len 个字节长度的数据，保存到 共享内存 (void *)mb + (size_t)iov->iov_base 地址处。
				ret = pread64(dev_fd, (void *)mb + (size_t)iov->iov_base, iov->iov_len, lba + doneLength);
				if(ret != iov->iov_len) {
					ent->rsp.scsi_status = 2;
					print("READ handling a command: ent->rsp.scsi_status = [%d]\n", ent->rsp.scsi_status);
				}
				else{
					//printMem((unsigned char *)((void *)mb + (size_t)iov->iov_base + lba + doneLength), (unsigned int)iov->iov_len);
				}
				printf("READ ret = [%d], remaining = [%d]\n", ret, remaining);	//ret = [4096], remaining = [4096] 表示4k一次读完
				remaining -= iov->iov_len;
				printf("READ remaining = [%d]\n", remaining);
				printf("READ doneLength = [%d]\n", doneLength);
				doneLength += iov->iov_len;
				printf("READ doneLength = [%d]\n", doneLength);
				
				print("READ handling a command: iov addr_1 = [%p]\n", iov);
				iov++;				//sizeof(struct iovec)=[16] 所以这个指针值+16
				print("READ handling a command: iov addr_2 = [%p]\n", iov);
			}
			ent->rsp.scsi_status = 0;
			break;
		default:
			printf("unknown command %x\n", cdb[0]);
			break;
	}

	return 0;
}

void poke_kernel(int fd)
{
	uint32_t buf = 0xabcdef12;

	print("poke kernel\n");
	//应用层把一包数据处理完毕，接下来
	//应用层通知内核，这包数据已经处理完毕，内核可以做数据已经传输完完结的操作了
	write(fd, &buf, 4);
	//这里会调用 uio驱动里面的 uio_write()函数
}

/*
功能: 处理1次 read 之后，内核写数据到共享内存之后 的内存数据
*/
int handle_commands(int fd, struct mailbox *mb)
{
	struct ofs_cmd_entry *ent;
	int did_some_work = 0;
	int num;

	ent = (void *) mb + mb->cmdr_off + mb->cmd_tail;	//TCMU命令的入口地址 //头指针在共享内存的高地址，尾指针在共享内存的低地址; 所以 TCMU 命令的起始地址 从tail开始
	printf("handle_commands: ent=[%p] mb=[%p] cmd_tail=[%lu] cmd_head=[%lu]\n", ent, mb, mb->cmd_tail, mb->cmd_head); 
	//ent=[0x7f80fe480080] mb=[0x7f80fe480000] cmd_tail=[0] cmd_head=[128]		//第1次
	//ent=[0x7f80fe480100] mb=[0x7f80fe480000] cmd_tail=[128] cmd_head=[256]	//第2次
	//ent=[0x7f80fe480180] mb=[0x7f80fe480000] cmd_tail=[256] cmd_head=[384]	//第3次
	print("handle_commands: ent->cmd_id = [%d]\n", ent->cmd_id);	//0
	print("handle_commands: ent->__pad1 = [%d]\n", ent->__pad1);	//0

	num=0;
	while (ent != (void *)mb + mb->cmdr_off + mb->cmd_head) {
	    printf("handle_commands: num=[%d]\n", num);
		num++;

		printf("handle_commands: &ent->hdr=[%p]\n", &ent->hdr);					//和 ent 的地址相同
		printf("handle_commands: ent->hdr.len_op=[%x]\n", ent->hdr.len_op);		//0x81: TCMU命令 0x80是长度，0x1是操作码
		if (ofs_hdr_get_op(&ent->hdr) == OFS_OP_CMD) {		//操作码匹配
			print("handle_commands: handling a command entry, len = [%d]\n", ofs_hdr_get_len(&ent->hdr));	//128:TCMU命令 0x80是长度
			handle_one_command(mb, ent);
		}
		else {
			print("handling a pad entry, len=[%d]\n", ofs_hdr_get_len(&ent->hdr));
		}
		print("handle_commands: ofs_hdr_get_len(&ent->hdr) = [%d]\n", ofs_hdr_get_len(&ent->hdr));			//128
		mb->cmd_tail = (mb->cmd_tail + ofs_hdr_get_len(&ent->hdr)) % mb->cmdr_size;		//0 + 128 % 65408 = 0 + 128 = 128; 尾指针后移 128 字节
		print("handle_commands: mb->cmd_tail = [%d]\n", mb->cmd_tail);					//128
		ent = (void *) mb + mb->cmdr_off + mb->cmd_tail;								//新的 TCMU 命令的起始地址
		print("handle_commands: ent addr2 = [%p]\n", ent);		//邮箱 + 256 偏移地址处
		did_some_work = 1;
	}

	if (did_some_work){
		poke_kernel(fd);
	}

	return 0;
}

union 
{
	int number;
	char s;
}test;

int testBigEndin()
{
	test.number=0x01000002;
	if(test.s==0x01){
		return 1;	
	}
	else{
		return 0;	
	}
}

int main(int argc, char * * argv)
{
	int fd;
	int logfd;
	void *map;
	int buf[100];
	int ret = -1;

	long int old_msec = 0;
	long int new_msec = 0;
	long int all_msec = 0;
	int	first_flag = 0;
	struct timeval cur_time;
	
	char uioname[256];
	char ofsname[256];
	
	//char data[10*1024*1024];
	//memset(data, 0, sizeof(data));
	
	if(argc != 3)
	{
		printf("usage: ./fc_ser /dev/uiox /home/file/testfilex\n");	
		return -1;
	}
	
	getNowTime();

	memset(uioname, 0, sizeof(uioname));
	memset(ofsname, 0, sizeof(ofsname));
	strcpy(uioname, argv[1]);
	strcpy(ofsname, argv[2]);
	printf("uioname=[%s]\n", uioname);
	printf("ofsname=[%s]\n", ofsname);

	printf("wangxiancai! pid=[%d]\n", getpid());
	logfd = open("./fc_ser.log", O_CREAT|O_RDWR|O_TRUNC);
	dup2(logfd, 1);
	close(logfd);

	getNowTime();
	
	if(testBigEndin() > 0){     
		printf("big\n");
	}
	else{
		printf("small\n");
	}
	
	printf("hello fctool!\n");
	/* We should be looking for UIO devices who's name starts with san-ofs here. */
	fd = open(uioname, O_RDWR);	// /dev/uio0 O_RDWR
	if (fd < 0) {
		print("could not open fd = [%d], errno = [%d], strerror = [%s]\n", fd, errno, strerror(errno));
		return 1;
	}
	printf("open [%s] succ fd=[%d]\n", uioname, fd);
	//内存映射大小: //OFS_RING_SIZE=(CMDR_SIZE + DATA_SIZE)=64K+8M
	map = mmap(NULL, (4096 * (16+2049)), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (map == MAP_FAILED) {
		print("could not mmap: %m\n", map);
		close(fd);
		return 1;
	}
	print("mmap addr = [%p]\n", map);

	mb = (struct mailbox *)map;

	printf("sizeof(char) = [%d]\n", sizeof(char));
	printf("sizeof(unsigned short) = [%d]\n", sizeof(unsigned short));
	printf("sizeof(unsigned int) = [%d]\n", sizeof(unsigned int));

	printf("sizeof(struct mailbox) = [%d]\n", sizeof(struct mailbox));
	print("mb->version = [%d]\n", mb->version);		//version:		    1:（如果是别的值，用户空间应该废弃）
	print("mb->flags = [%d]\n", mb->flags);			//flags:		    1:（如果是别的值，用户空间应该废弃）
	print("mb->cmdr_off = [%d]\n", mb->cmdr_off);	//cmdr_off:		    command ring 在内存区域的起始位置的偏移量
	print("mb->cmdr_size = [%d]\n", mb->cmdr_size);	//cmdr_size:		command ring 区域的大小。这不需要2的幂来表示
	print("mb->cmd head = [%d]\n", mb->cmd_head);	//cmd_head:			由内核修改，表示一个command已经放置到ring中
	print("mb->cmd tail = [%d]\n", mb->cmd_tail);	//cmd_tail:			由用户空间修改，表示一个command已经处理完成

	//memcpy(data, map, sizeof(data));
	printMem((unsigned char*)mb, (4096 * (16+5)));

	char *path = "/dev/uiox /home/file/testfile";
	dev_fd = open(ofsname, O_RDWR | O_LARGEFILE);
	if(dev_fd < 0)
	{
		print("could not open %s", path);
		return 1;
	}

	//TODO: 这里为什么要干一次？
	handle_commands(fd, mb);

	all_msec = 0;
	while(1) {
		printf("read ...\n");
		ret = read(fd, buf, 4); //会阻塞在这里 因为 uio_read() 里面有让这个内核进程睡眠。
		//这里会调用 uio驱动里面的 uio_read()函数

		getNowTime();
		print("mb->version = [%d]\n", mb->version);		//version:		    1:（如果是别的值，用户空间应该废弃）
		print("mb->flags = [%d]\n", mb->flags);			//flags:		    1:（如果是别的值，用户空间应该废弃）
		print("mb->cmdr_off = [%d]\n", mb->cmdr_off);	//cmdr_off:		    command ring 在内存区域的起始位置的偏移量; TCMU命令的偏移地址.
		print("mb->cmdr_size = [%d]\n", mb->cmdr_size);	//cmdr_size:		command ring 区域的大小。这不需要2的幂来表示
		print("mb->cmd head = [%d]\n", mb->cmd_head);	//cmd_head:			由内核修改，表示一个command已经放置到ring中
		print("mb->cmd tail = [%d]\n", mb->cmd_tail);	//cmd_tail:			由用户空间修改，表示一个command已经处理完成
		printMem((unsigned char*)mb, (4096 * (16+5)));

		//print("handle_commands:\n");
		handle_commands(fd, mb);
	}

	return 0;
}


/*

    int fd, dev_fd;
    char buf[256];
    unsigned long long map_len;
    void *map;
     
    fd = open("/sys/class/uio/uio0/name", O_RDONLY);
    ret = read(fd, buf, sizeof(buf));
    close(fd);
    buf[ret-1] = '\0'; // null-terminate and chop off the \n
     
    // we only want uio devices whose name is a format we expect 
    if (strncmp(buf, "tcm-user", 8))
        exit(-1);
     
    // Further checking for subtype also needed here 
     
    fd = open(/sys/class/uio/%s/maps/map0/size, O_RDONLY);
    ret = read(fd, buf, sizeof(buf));
    close(fd);
    str_buf[ret-1] = '\0'; // null-terminate and chop off the \n
     
    map_len = strtoull(buf, NULL, 0);
     
    dev_fd = open("/dev/uio0", O_RDWR);
    map = mmap(NULL, map_len, PROT_READ|PROT_WRITE, MAP_SHARED, dev_fd, 0);


	while (1) {
		char buf[4];
		int ret = read(dev_fd, buf, 4);
	
		handle_device_events(dev_fd, map);
	}

	//#include <linux/target_core_user.h>
	int handle_device_events(int fd, void *map)
	{
		struct tcmu_mailbox *mb = map;
		struct tcmu_cmd_entry *ent = (void *) mb + mb->cmdr_off + mb->cmd_tail;
		int did_some_work = 0;

		//Process events from cmd ring until we catch up with cmd_head
		while (ent != (void *)mb + mb->cmdr_off + mb->cmd_head) {
			if (tcmu_hdr_get_op(ent->hdr.len_op) == TCMU_OP_CMD) {
				uint8_t *cdb = (void *)mb + ent->req.cdb_off;
				bool success = true;
				// Handle command here.
				printf("SCSI opcode: 0x%x\n", cdb[0]);
	
				// Set response fields
				if (success){
					ent->rsp.scsi_status = SCSI_NO_SENSE;
				}
				else{
					// Also fill in rsp->sense_buffer here
					ent->rsp.scsi_status = SCSI_CHECK_CONDITION;
				}
			}
			else if (tcmu_hdr_get_op(ent->hdr.len_op) != TCMU_OP_PAD) {
				// Tell the kernel we didn't handle unknown opcodes
				ent->hdr.uflags |= TCMU_UFLAG_UNKNOWN_OP;
			}
			else {
				// Do nothing for PAD entries except update cmd_tail
			}
	
			// update cmd_tail
			mb->cmd_tail = (mb->cmd_tail + tcmu_hdr_get_len(&ent->hdr)) % mb->cmdr_size;
			ent = (void *) mb + mb->cmdr_off + mb->cmd_tail;
			did_some_work = 1;
		}
		// Notify the kernel that work has been finished
		if (did_some_work) {
			uint32_t buf = 0;
			write(fd, &buf, 4);
		}
		return 0;
	}
*/





