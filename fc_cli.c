#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/time.h>

void consumeTime(struct timeval run_begin, long int * msec)	//TODO
{
	struct timeval run_end;
	memset(&run_end, 0, sizeof(struct timeval));
	
	gettimeofday(&run_end, NULL);
	*msec = (run_end.tv_sec-run_begin.tv_sec)*1000 + (run_end.tv_usec-run_begin.tv_usec)/1000;	//unit:ms
}

int main(int argc, char * * argv)
{
	int fd = -1;	
	char filename[128];
	long int data;
	long int count;

	double fdata = 0.0;
	double fgdata = 0.0;
	double ftime = 0.0;
	
	//char buf[1048576]; //1*1024*1024	 
	//4*1024*1024 = 4294967296 = 4G
	//4*1024*1024 = 4194304 = 4M
	int i = 0;
	long int len = -1;
	int offset = 0;
	long int ret = -1;
	char * buf = NULL;
	
	//long int msec;									//TODO
	//struct timeval run_begin;						//TODO
	//memset(&run_begin, 0, sizeof(struct timeval));	//TODO
	//gettimeofday(&run_begin, NULL);					//TODO

	memset(filename, 0, sizeof(filename));

	if(argc != 4)
	{
		printf("usage: fc_cli diskname data count");
		return -1;
	}
	strcpy(filename, argv[1]);
	data = atol(argv[2]);
	count = atol(argv[3]);
	printf("fc_cli: diskname=[%s] data=[%ld] count=[%ld]\n", filename, data, count);
	
	buf = (char*)malloc(data);
	if(buf == NULL)
	{
		perror("malloc");
		return -1;
	}

	fd = open(filename, O_RDWR);
	if(fd < 0)
	{
		perror("open");
		return -1;
	}

	memset(buf, 'a', sizeof(buf));
	//len = sizeof(buf);
	len = data;

	//consumeTime(run_begin, &msec);	//TODO
	//printf("fc_cli begin: [%ld]ms\n", msec);

	for(i=0; i<count; i++)
	{
		offset = 0;
		/*	
		ret = pwrite64(fd, buf, len, 10);
		if(ret != len) {
			printf("pwrite64 err ret=[%d], errno=[%d] len=[%d]\n", ret, errno, len);
			return -1;
		}
		*/
		ret = write(fd, buf, len);
		if(ret != len) {
			printf("write err ret=[%d], errno=[%d] len=[%d]\n", ret, errno, len);
			return -1;
		}
	}

	//consumeTime(run_begin, &msec);	//TODO
	//printf("fc_cli end: [%lld]ms\n", msec);
	
	//fdata = (double)data / 1024.0 / 1024.0 * (double)count;
	//fgdata = fdata / 1024.0;
	//ftime = (double)msec / 1000.0;
	
	//printf("\n*****************************************************\n");
	//printf("data:[%.4fM]=[%.4fG]\n", fdata, fgdata);
	//printf("time:[%lldms]=[%.4fs]\n", msec, ftime);
	//printf("speed:[%.4fM/S]\n", fdata/ftime);
	printf("*****************************************************\n");
	
	if(buf != NULL)
	{
		free(buf);
		buf = NULL;
	}

	close(fd);

	return 0;
}




