/*
 * 这里简单实现了一个CTF线下攻防赛中pwn题的流量截取工具
 * 
 *
 * TODO 
 *  关键内存监控模块（段、堆等）
 *  指定代码hook等 
 */


#include <fcntl.h>
#include <stdio.h> 
#include <unistd.h> 
#include <stdlib.h> 
#include <sys/types.h> 
#include <string.h>
#include <time.h>
#include <semaphore.h>
#include <libgen.h>
#include <signal.h>
#include <pthread.h>
#include <wait.h>

#define BUFSIZE 4096   //缓冲区大小
#define FILEPATH_SIZE 128
#define PATH_MAX 128
#define OPEN_FLAG O_RDWR|O_CREAT
#define OPEN_MODE 00777
#define INIT_V    0    //信号量初始为0

typedef struct
{
	char logfile[100];
	FILE *fp;   
}Log;

char *self_filename; 
char tmp_filename[FILEPATH_SIZE];
int pipe_read[2], pipe_write[2], pipe_log[2];
pthread_mutex_t pipeMutex;

void do_memmap();
void rand_str(char *out, int len);
char *getpath();
void release(char *self_filename, char *tmp_filename);

//generate a random string
void rand_str(char *out, int len)
{
	int i; 
	srand((int)time(NULL)); 
	for (i=0; i<len - 1; i++) 
	{ 
		unsigned int rui = (unsigned int) rand();
		unsigned int opt = (unsigned int) rand();
		if (opt & 1)
			out[i] = 'A' + rui % 26;
		else
			out[i] = 'a' + rui % 26;
	}	
	out[i] = '\0';
}

char *getpath()
{
	static char buf[PATH_MAX];
	int i;
	int rslt = readlink("/proc/self/exe", buf, PATH_MAX);
	if (rslt < 0 || rslt >= PATH_MAX)
   	{
       	 return NULL;
    	}
    	buf[rslt] = '\0';
    	for (i = rslt; i >= 0; i--)
    	{
       	 if (buf[i] == '/')
        	{
            		buf[i + 1] = '\0';
            		break;
        	}
    	}
    	return buf;
}

//release payload into /tmp directory
void release(char *self_filename, char *tmp_filename)
{
	char self_path[200];
	memset(self_path, 0, sizeof(self_path));
	strcat(self_path, getpath());
	strcat(self_path, self_filename);
	//printf("%s\n", self_path);
	FILE *fp = fopen(self_path, "rb");
	if (fp == NULL)
	{
		perror("fopen");
		exit(0);
	}
	if(fseek(fp, 0, SEEK_END) == -1)
	{
		perror("fseek");
		exit(0);
	}
	int file_size = ftell(fp);   //get self file-size
	char *buf = (char*)malloc(file_size + 1);
	if(fseek(fp, 0, SEEK_SET) == -1)
	{
		perror("fseek");
		exit(0);
	}
	fread(buf, 1, file_size+1, fp);
	/*
	 * Read all bytes into buf. It seems there is no need to read all,
	 * but when I try to read specifical bytes with fseek, I get some kinds of strange bugs
	 */
	fclose(fp);

	//payload length stores in the final 4 bytes 
	unsigned int  payload_len = *((unsigned int*)(buf + file_size - 4));
	char tmp_dir[100] = "/tmp/.";//add '.' to directory name to make it invisible
	strcat(tmp_dir, self_filename);
	char cmd[100];
	if (access(tmp_dir, F_OK) != 0)
	{
		memset(cmd, 0, sizeof(cmd));
		sprintf(cmd, "mkdir -p %s", tmp_dir); 
		system(cmd);
	}

	char tmp_path[FILEPATH_SIZE];
	memset(tmp_path, 0, sizeof(tmp_path));
	sprintf(tmp_path, "%s/%s", tmp_dir, tmp_filename);	

	//检查文件是否存在
	if (access(tmp_path, F_OK) != 0){ //文件不存在
		fp = fopen(tmp_path, "wb");
		if (fp == NULL)
			exit(0);
		fwrite(buf + file_size - 4 - payload_len, 1, payload_len, fp);
		fclose(fp);
	}
	//检查文件是否具有可执行权限
	if (access(tmp_path, X_OK) != 0)
	{
		memset(cmd, 0, sizeof(cmd));
		sprintf(cmd, "chmod +x %s", tmp_path);
		system(cmd);
	}
}



void init_log(Log *logv, char *self_filename)
{
	time_t now;
	struct tm *tm_now;
	time(&now);
	tm_now = localtime(&now);
	char time_str[100];
	sprintf(time_str,"%04d-%02d-%02d,%02d-%02d-%02d", tm_now->tm_year + 1900, tm_now->tm_mon, 
			tm_now->tm_mday, tm_now->tm_hour, tm_now->tm_min, tm_now->tm_sec);
	sprintf(logv->logfile, "/tmp/.%s/%s.log", self_filename, time_str); 
	logv->fp = fopen(logv->logfile, "wb");
	if (logv->fp == NULL)
	{
		perror("popen");
		exit(0);
	}
}


void mlog(Log *logv, char *content, int len)
{
	fwrite(content, 1, len, logv->fp); 
	fflush(logv->fp);
}

void close_log(Log *logv)
{
	fclose(logv->fp);
}


//buffer filter
int filter(char *buf)
{
	char format[3][20] = {"flag", "cat"};
	int size_filter = 0;  //edit format and size_filter to add your own flag_str
	int j;
	for (j=0;j<size_filter;j++)
		if (strstr(buf, format[j]))
			return 1;
	return 0;
}

int isPrintable(char c)
{
	if ((c>='a' && c<='z') || (c>='A' && c<='Z') || (c>='0' && c<='9'))
		return 1;
	char printable[] = "!\"#$%&\\'()*+,-./:;<=>?@[]^_`{|}~ \n";
	int i;
	for (i=0; printable[i] != '\0'; i++)
		if (c == printable[i])
			return 1;
	return 0;
}

void do_output()
{
	char buffer[BUFSIZE + 1];
	char c;
	while(1)
	{
		int ret = read(pipe_write[0] , &c, 1);   //读取payload程序输出
		if (ret == 1)
		{
			putchar(c); 
			write(pipe_log[1], &c, 1);  //write it into LogPipe
		}
	}
}

void do_input()
{			  
	char c;
	char buffer[BUFSIZE+1];
	while(1)
	{
		int rsize = read(0, &buffer, BUFSIZE); //read input from terminal
		// int i = 0;
		// buffer[i++] = c;
		// if(c=='\n' || i >= BUFSIZE-1) 
		// {
		// 	buffer[i] = '\0';
		// 	//there we do nothing right now
		// 	i=0;
		// }
		int res = write(pipe_read[1], buffer, rsize); 
		//printf("write result is %d\n", res);
		// pthread_mutex_lock(&pipeMutex);
		write(pipe_log[1], buffer, rsize);  //write it into LogPipe
		// pthread_mutex_unlock(&pipeMutex);
	}
}

char* addHex(char *in, int length)
{
	static char out[BUFSIZE];
	memset(out, 0, sizeof(out));
	int i=0;
	strcat(out, "[");
	while(i<length)
	{
		if ( ! isPrintable( in[i] ) )
		{
			int j = i+1;
			while ( !isPrintable( in[j] ) && j < length ) 
			{ 
				j++; 
			}
			int k;
			for (k=i; k<j; k++)
			{
				char hex[10];
				sprintf(hex, "\\x%02x", (unsigned char)in[k]);
				strcat(out, hex);
			}
			strcat(out, ", ");
			i = j;
		} 
		i++;
	}
	strcat(out, "]\n");
	if(strlen(out) > 3)
		strcat(out, "\n");
	else
		out[0] = 0;
	return out;
}

void do_log()
{
	Log logv;
	init_log(&logv, self_filename);
	char buffer[BUFSIZE+1];  
	memset(buffer, 0, BUFSIZE);
	int i;
	char c;
	while((read(pipe_log[0], &c, 1)) == 1)
	{
		buffer[i++] = c;
		if(c=='\n' || i>=BUFSIZE-1)
		{
			if (strstr(buffer, "**exit"))
				break;
			buffer[i] = '\0';
			mlog(&logv, buffer, i);
			char *out = addHex(buffer, i);
			mlog(&logv, out, strlen(out));
			i=0;
		}
	}
	if (i!=0)
		mlog(&logv, buffer, i-1);
}

void do_memmap()
{
	FILE *popen_fp;
	char output_buf[BUFSIZE+1];
	char cmd[100];
	sprintf(cmd, "pidof %s", tmp_filename);
	popen_fp = popen(cmd, "r");
	while(1)
	{
		memset(output_buf,0,sizeof(output_buf));
		size_t size = fread(output_buf, 1, BUFSIZE, popen_fp);
		if (size > 0)
			break;
		//printf("wait\n");
	}

	sprintf(cmd, "cat /proc/`pidof %s`/maps", tmp_filename);
	popen_fp = popen(cmd, "r");
	memset(output_buf,0,sizeof(output_buf));
	while(!feof(popen_fp))
	{
		size_t size = fread(output_buf, 1, BUFSIZE, popen_fp);
		write(pipe_log[1], output_buf, size);
		memset(output_buf,0,sizeof(output_buf));
	}
	write(pipe_log[1], "\n\n", 2);
}

int run_payload(char *self_filename, char *tmp_filename, int (*filter)(char*))
{
	if(pipe(pipe_read) < 0 || pipe(pipe_write) < 0 || pipe(pipe_log) < 0)
	{
		perror("create read pipe failed\n");
		exit(0);
	}

	if(fork() == 0)	
	{    
		
		dup2(pipe_read[0], STDIN_FILENO) ; 
		close(pipe_read[0]);
		close(pipe_read[1]);   

		dup2(pipe_write[1], STDOUT_FILENO); 
		close(pipe_write[1]);
		close(pipe_write[0]);  

		char payload_fullpath[FILEPATH_SIZE];
		sprintf(payload_fullpath, "/tmp/.%s/%s", self_filename, tmp_filename);
		system(payload_fullpath);
		
		close(pipe_log[0]);
		char exitflag[] = "\n**exit [auto generated by shell program]**\n";
		//write(pipe_log[1], exitflag, strlen(exitflag));
		//remove(payload_fullpath);  //remove tmp file we just create
	}
	else
	{
		close(pipe_read[0]);
		close(pipe_write[1]);
		pthread_t tids[4];
		pthread_create(&tids[0], NULL, (void*)do_log, NULL);
		do_memmap();
		pthread_mutex_init(&pipeMutex, NULL);
		pthread_create(&tids[1], NULL, (void*)do_output, NULL);
		pthread_create(&tids[2], NULL, (void*)do_input, NULL);
		pthread_join(tids[1], NULL);
	}
	return 0;
}

int main(int argc, char **argv)
{
	setbuf(stdin, 0);
	setbuf(stdout, 0);
	rand_str(tmp_filename, 10);
	/*
	 * I generate a new and uniqe tmp_filename, so that I don't need to care about 
	 * situation which more than one pid when I try to fetch pid of payload program
	 * through pidof command
	 */
	self_filename = basename(argv[0]);
	//printf("filename is %s\n", self_filename);
	
	release(self_filename, tmp_filename); 
	run_payload(self_filename, tmp_filename, filter);
	return 0;
}  
