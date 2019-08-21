#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <glib.h>
#include <dirent.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <attr/xattr.h>
#include <sys/wait.h>

struct digest_t {
        char *name;
        gnutls_digest_algorithm_t type;
};

gnutls_digest_algorithm_t dig_alg = GNUTLS_DIG_UNKNOWN;

struct digest_t digest_types[] = {
        {"MD5", GNUTLS_DIG_MD5},
        {"SHA1", GNUTLS_DIG_SHA1},
        {"RMD160", GNUTLS_DIG_RMD160},
        {"MD2", GNUTLS_DIG_MD2},
        {"SHA256", GNUTLS_DIG_SHA256},
        {"SHA384", GNUTLS_DIG_SHA384},
        {"SHA512", GNUTLS_DIG_SHA512},
        {"SHA224", GNUTLS_DIG_SHA224},
        {NULL, 0}
};

int set_opt=0;
int verify_opt=0;
int export_opt=0;
int import_opt=0;
int list_hash_opt=0;

int user=1;

int initqdepth=0;

int quiet=0;

int update_only=0;

int file_list=0;

int *digests;
int n_digests = sizeof digest_types / sizeof(struct digest_t);

int is_dir(char *name);
int walk_dir(GQueue *worknames, int recursive);
int process_file(char *name);
int walk_down_dir(char *directory, GQueue *worknames);
int check_file(char *name);
int process_filelist(char *name);
int set_hash(const char *name, const char *hash, int size, int dig);

ssize_t (*mygetattr)(const char *path, const char *name, void *value, size_t size) = lgetxattr;
int (*mysetattr)(const char *path, const char *name, const void *value, size_t size, int flags) = lsetxattr;
int (*mystat)(const char *pathname, struct stat *buf) = stat;
ssize_t (*mylistattr)(const char *path, char *list, size_t size) = llistxattr;

void
print_help()
{
        fprintf(stderr, "Usage: hasher [-r] [-d digest [-d digest ...]] [-s] [-v] [-h] [-l] [-q] [-i] [-e] [-p] files\n");
        fprintf(stderr, "\t-r recursive\n\t-d digest (type -d help)\n\t-s set digest\n\t-e export digest\n\t-p import digest\n\t-v verify digest\n\t-h print this help\n\t-l follow symlinks\n\t-q quiet\n\t-i list computed hashes\n");
}

int
main(int argc, char *argv[]) 
{
        GQueue *worknames=g_queue_new();
        char recursive=0;
        int opt;
        int dig=0;
        int i;
        gnutls_hash_hd_t digest;
        char *filelist=NULL;

        digests = calloc(n_digests+1, sizeof(int));

        if(argc<=1) {
                print_help();
                return 1;
        }

        while((opt = getopt(argc, argv, "rd:svlhqaiep")) != -1) {
                switch(opt) {
                        case 'r':
                                recursive = 1;
                                break;
                        case 'd':
                                if(strcmp(optarg, "help") == 0) {
                                        fprintf(stderr, "Available digests:");
                                        for(i=0; digest_types[i].name != NULL; i++) {
                                                fprintf(stderr, " %s", digest_types[i].name);
                                        }
                                        fprintf(stderr, "\n");
                                        return 0;
                                }
                                for(i=0; digest_types[i].name != NULL; i++) {
                                        if(strcmp(digest_types[i].name, optarg) == 0) {
                                                digests[dig++] = i;
                                                if(dig >= n_digests) {
                                                        fprintf(stderr, "Too many digests requested.\n");
                                                        return 1;
                                                }
                                                if(gnutls_hash_init(&digest, digest_types[i].type)!=0) {
                                                        fprintf(stderr, 
                                                                  "Cannot init gnutls hash functions\n");
                                                        return 1;
                                                }
                                                gnutls_hash_deinit(digest, NULL);
                                                break;
                                        }
                                }
                                if(digest_types[i].name == NULL) {
                                        fprintf(stderr, "Unknown digest type %s\n", optarg);
                                        return 1;
                                }
                                break;
                        case 'v':
                                verify_opt = 1;
                                break;
                        case 's':
                                set_opt = 1;
                                break;
                        case 'e':
                                export_opt = 1;
                                quiet=1;
                                break;
                        case 'p':
                                import_opt = 1;
                                file_list = 1;
                                break;
                        case 'l':
                                mystat = stat;
                                mygetattr = getxattr;
                                mysetattr = setxattr;
                                mylistattr = listxattr;
                                break;
                        case 'i':
                                list_hash_opt = 1;
                                break;
                        case 'q':
                                quiet=1;
                                break;
                        case 'h':
                        default:
                                print_help();
                                return 1;
                }
        }

        n_digests=dig;
        digests[dig] = -1;

        if(dig == 0) {
                /* default to MD5 */
                n_digests = 1;
                digests[0] = 0;
        }

        if(set_opt == 1 && verify_opt == 1) {
                fprintf(stderr, "set and verify options are mutually exclusive\n");
                return 1;
        }

        if(export_opt == 0 && import_opt == 0 && 
           set_opt == 0 && verify_opt == 0 && !quiet) {
                verify_opt = 1;
        }

        if(optind == argc) {
                g_queue_push_tail(worknames, strdup("."));
        }

        if(file_list) {
                filelist=argv[optind];
        } else {
                while(optind < argc) {
                        g_queue_push_tail(worknames, strdup(argv[optind++]));
                        initqdepth++;
                }
        }

        if(! file_list)
                return walk_dir(worknames, recursive);
        else
                return process_filelist(filelist);
}

int
is_dir(char *name) 
{
        struct stat sb;
        int ret;

        ret = mystat(name, &sb);
        if(ret != 0) {
                if(!quiet)
                        fprintf(stderr, "error stating file %s ", name);
                perror(NULL);
                return -1;
        }
        return S_ISDIR(sb.st_mode);
}

int
walk_dir(GQueue *worknames, int recursive) 
{
        char *item;
        int ret;
        int err_code=0;

        while((item=g_queue_pop_head(worknames))!=NULL) {
                if(initqdepth >= 0)
                        initqdepth--;
                ret = is_dir(item);
                if(ret == -1 && !quiet) {
                        fprintf(stderr, "Cannot stat %s\n", item);
                        err_code = -1;
                }
                if(ret == 0) {
                        if((!update_only) || (update_only && !check_file(item))) {
                                int r;
                                if((r=process_file(item))!=0)
                                        if(r > err_code)
                                                err_code = r;
                        }
                }
                if(ret == 1) {
                        if(recursive || initqdepth >= 0) {
                                if(!quiet)
                                        fprintf(stderr, "Walking down %s\n", item);
                                if(walk_down_dir(item, worknames)!=0)
                                        err_code=-1;
                        } else {
                                if(!quiet)
                                        fprintf(stderr, 
                                                "%s is directory, skipped in non-recursive mode.\n", item);
                        }
                }
                free(item);
        }
        return err_code;
}

int
process_filelist(char *name)
{
        FILE *in = fopen(name, "rb");
        char buff[4096];
        int lf_pos;
        int err_code=0;
       
        if(in == NULL) {
                return 1;
        }

        while(!feof(in)) {
                memset(buff, 0, 4096);
                if(!fgets(buff, 4096, in))
                        break;
                lf_pos=strlen(buff);
                lf_pos--;
                while(buff[lf_pos] == '\n' || buff[lf_pos] == '\r')  {
                        buff[lf_pos] = 0;
                        lf_pos--;
                }
                if(import_opt) {
                        char *digest_name=NULL;
                        char *digest=NULL;
                        char *fn=NULL;
                        int digest_no=-1;
                        int i;

                        digest_name = buff;

                        for(lf_pos=0; lf_pos < strlen(buff); lf_pos++) {
                                if(buff[lf_pos] == ' ') {
                                        buff[lf_pos] = 0;
                                        lf_pos++;
                                        digest = &buff[lf_pos];
                                        break;
                                }
                        }

                        while(buff[lf_pos] != 0) {
                                if(buff[lf_pos] == ' ') { 
                                        buff[lf_pos] = 0;
                                        lf_pos++;
                                        fn = &buff[lf_pos];
                                        break;
                                }
                                lf_pos++;
                        }

                        for(i=0; digest_types[i].name != NULL; i++) {
                                if(strcmp(digest_types[i].name, digest_name) == 0) {
                                        digest_no = i;
                                        break;
                                }
                        }
                        if(digest_no == -1) {
                                fprintf(stderr, "Unknown digest: %s\n", digest_name);
                                continue;
                        }

                        set_hash(fn, digest, -1, digest_no);
                } else {
                        if((!update_only) || (update_only && !check_file(buff))) {
                                int r;
                                if((r=process_file(buff))!=0)
                                        if(r > err_code)
                                                err_code = r;
                        }
                }
        }
        fclose(in);
        return err_code;
}

char *
read_attr(const char *name, char *attr)
{
        char attr_name[100];
        int ret;
        char buff[200];

        memset(buff, 0, 200);
        if(user == 1) {
                snprintf(attr_name, 100, "user.extattr-file-integrity.%s", attr);
                ret = mygetattr(name, attr_name, buff, 200);
                if(ret < 1 && !quiet) {
                        if(errno == ENOATTR) {
                                fprintf(stderr, "User checksum not set on '%s' nothing to verify.\n", name);
                        } else {
                                fprintf(stderr, "Cannot get xattr on %s ", name);
                                perror("");
                        }
                        return NULL;
                }
        }
        return strdup(buff);
}

int
list_hash(const char *name) 
{
        int size=4096;
        int ret;
        char *buff;
        int pos;

        do {
                buff = calloc(size,1);

                ret = mylistattr(name, buff, size);
                if(ret < 0 && errno == ERANGE)
                        size *= 2;
                else 
                        break;
                free(buff);
        } while(1);
        if(ret < 0)
                return -1;

        pos = 0;
        while(pos < ret) {
                if(strncmp(&buff[pos], "user.extattr-file-integrity.", 28) == 0) {
                        char *value;
                        printf("Stored hash type: %s ", &buff[pos+28]);
                        value = read_attr(name, &buff[pos+28]);
                        if(value != NULL) {
                                printf("%s\n", value);
                                free(value);
                        }
                }
                pos += strlen(buff)+1;
        }
        return 0;
}

int
set_hash(const char *name, const char *hash, int size, int dig)
{
        int ret;
        char attr_name[100];
        char hash_hex[200];
        int i;
        int pos=0;

        if(size > 0) {
                for(i=0; i < size; i++) {
                        pos+=snprintf(&hash_hex[pos], 200-pos, "%02x", (int)((unsigned char)hash[i]));
                }
        } else {
                strcpy(hash_hex, hash);
                pos=strlen(hash_hex);
        }

        if(user == 1) {
                snprintf(attr_name, 100, "user.extattr-file-integrity.%s", digest_types[dig].name);

                ret = mysetattr(name, attr_name, hash_hex, pos, 0);

                if(ret != 0 && !quiet) {
                        fprintf(stderr, "Cannot set xattr on %s ", name);
                        perror("");
                        return -1;
                }
        }
        return 0;
}

int
verify_hash(const char *name, const char *hash, int size, int dig)
{
	int f_ret;
        char hash_hex[200];
        int pos = 0;
        int i;
        char *buff;

        for(i=0; i < size; i++) {
                pos+=snprintf(&hash_hex[pos], 200-pos, "%02x", (int)((unsigned char)hash[i]));
        }

        if(list_hash_opt)
                list_hash(name);

	if(user == 1) {
                buff = read_attr(name, digest_types[dig].name);

                if(buff == NULL) {
                        return 3;
                }

        	if(memcmp(buff, hash_hex, size) != 0) {
	                if(!quiet)
	                        fprintf(stderr, "User checksum type %s ERROR on %s\n", digest_types[dig].name, name);
	                f_ret = 4;
	        } else {	
	                if(!quiet)
	                        fprintf(stderr, "User checksum type %s verified OK on %s\n", digest_types[dig].name, name);
                        f_ret = 0;
	        }
	}
        return f_ret;
}

int
check_file(char *name)
{
        int ret;
        char attr_name[100];
        int checktime;
        struct stat sb;
       
        memset(attr_name, 0, sizeof(attr_name));

        ret = mygetattr(name, "system.checktime", attr_name, sizeof(attr_name));
        if(ret <= 0 && errno != ENOATTR)
                perror("getxattr");
        else
                ret = 0;
        ret |= mystat(name, &sb);

        checktime = atoi(attr_name);
        
        if((ret == 0) && (sb.st_ctime <= checktime)) {
                if(!quiet) {
                        fprintf(stderr, "File %s not changed, skip.\n", name);
                }
                return 1;
        } else {
                if(!quiet) {
                        fprintf(stderr, "File %s changed, recompute hash.\n", name);
                }
                return 0;
        }
}

int
process_file(char *name) 
{
        FILE *in;
        char buff[16384];
        int usable=0;
        int ret;
        gnutls_hash_hd_t digest[n_digests];
        int hash_len[n_digests];
        unsigned char *hash[n_digests];
        int i,j;
        int err_code=0;

        for(i=0; i < n_digests; i++) {
                gnutls_hash_init(&digest[i], digest_types[digests[i]].type);

                hash_len[i] = gnutls_hash_get_len(digest_types[digests[i]].type);

                hash[i] = calloc(1, hash_len[i]);
        }

        if(!quiet)
                fprintf(stderr, "Processing %s...\n", name);
        in = fopen(name, "rb");

        if(!in) {
                if(!quiet) {
                        fprintf(stderr, "Cannot open file ");
                        perror(name);
                }
                return 2;
        }

        while(!feof(in)) {
                ret = fread(buff, 1, 16384, in);
                if(ret < 1) {
                        break;
                }
                usable = 1;
                for(i=0; i < n_digests; i++) 
                        gnutls_hash(digest[i], buff, ret);
        }

        fclose(in);

        if(usable == 0) {
                return 0;
        }


        for(i=0; i < n_digests; i++) {
                gnutls_hash_deinit(digest[i], hash[i]);

                if(!quiet) {
                        fprintf(stderr, "Actual hash of %s is %s: ", name, digest_types[digests[i]].name);

                        for(j=0; j < hash_len[i]; j++) {
                                fprintf(stderr, "%02x", hash[i][j]);
                        }

                        fprintf(stderr, "\n");
                }

                if(set_opt) {
                        err_code|=set_hash(name, (const char*)hash[i], hash_len[i], digests[i]);
                }

                if(export_opt) {
                        printf("%s ", digest_types[digests[i]].name);
                        for(j=0; j < hash_len[i]; j++) {
                                printf("%02x", hash[i][j]);
                        }
                        printf(" %s\n", name);
                }

                if(verify_opt) {
                        err_code|=verify_hash(name, (const char*)hash[i], hash_len[i], digests[i]);
                }

                free(hash[i]);
        }

        return err_code;
}

int
walk_down_dir(char *directory, GQueue *worknames) 
{
        DIR *dir;
        struct dirent *de;
        char buff[PATH_MAX+NAME_MAX];

        dir = opendir(directory);

        if(!dir) {
                perror(directory);
                return -1;
        }

        while((de = readdir(dir))) {
                if(strcmp(de->d_name, ".") == 0)
                        continue;
                if(strcmp(de->d_name, "..") == 0)
                        continue;
                snprintf(buff, PATH_MAX+NAME_MAX, "%s/%s", directory, de->d_name);
                if(!quiet)
                        fprintf(stderr, "Adding %s\n", buff);
                g_queue_push_head(worknames, strdup(buff));
        }

        closedir(dir);
        return 0;
}
