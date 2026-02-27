#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <pthread.h>
#include <netinet/tcp.h>

#include <string>
#include <vector>
#include <map>

#include <sqlite3.h>

#include "common.h"

#define PORT 4012

char *cmdbuf;
int bufsize, buflen;

pthread_mutex_t map_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t db_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t file_modif_mutex = PTHREAD_MUTEX_INITIALIZER;

struct file_info
{
    file_data data;
    pthread_mutex_t access_mutex = PTHREAD_MUTEX_INITIALIZER;
    int client[2], connected[2];
    file_cursor cursors[2];
    int initialized = 0;
    int fileid = 0;
};

struct thread_info
{
    pthread_t thread_id;
    int client_sd;

    std::string logged_username;
    int logged_user_id;
    int logged_in = 0;

    int edit_mode;
    file_info* edited_file;
};

std::map<std::string, file_info*> open_files;
sqlite3* database;

sqlite3_stmt* list_files, *get_file, *add_file, *delete_file, *rename_file, *update_contents, *get_user, *get_user_id, *add_user, *allow_user_file, *disallow_user_file, *make_public, *make_private, *get_allowed;

void handle_error(int cod, int is_thread = 0, int sql_error = SQLITE_OK)
{
    if(is_thread)
        printf("[Server thread] ");
    else
        printf("[Server] ");
    switch (cod)
    {
    case 1: printf("Eroare la realloc(): "); fflush(NULL); perror(0); break;
    case 2: printf("Eroare la deschidere socket: "); fflush(NULL); perror(0); break;
    case 3: printf("Eroare la setare optiune pe socket: "); fflush(NULL); perror(0); break;
    case 4: printf("Eroare la bind(): "); fflush(NULL); perror(0); break;
    case 5: printf("Eroare la listen(): "); fflush(NULL); perror(0); break;
    case 7: printf("Eroare la write() spre client: "); fflush(NULL); perror(0); break;
    case 9: printf("Eroare la read() de la client: "); fflush(NULL); perror(0); break;
    case 11: printf("Eroare la malloc(): "); fflush(NULL); perror(0); break;
    case 13: printf("Mesaj invalid primit de la client (in mod edit).\n"); break;
    case 14: printf("Eroare la deschidere baza de date (memorie insuficienta).\n"); break;
    case 15: printf("Eroare la deschidere baza de date: %s\n", sqlite3_errstr(sql_error)); break;
    case 16: printf("Eroare la preparare statement-uri tabele: %s\n", sqlite3_errstr(sql_error)); break;
    case 17: printf("Eroare la initializare tabele: %s\n", sqlite3_errstr(sql_error)); break;
    case 18: printf("Eroare la preparare statement-uri generale: %s\n", sqlite3_errstr(sql_error)); break;
    case 19: printf("Eroare la activare chei straine: %s\n", sqlite3_errstr(sql_error)); break;
    case 20: printf("Eroare la bind parameter: %s\n", sqlite3_errstr(errno)); break;
    case 21: printf("Eroare la query/step: %s\n", sqlite3_errstr(errno)); break;
    case 23: printf("Eroare la column_text: %s\n", sqlite3_errstr(errno)); break;
    case 25: printf("Eroare la cautare autor al unui fisier (baza de date corupta?)\n"); break;
    default: printf("Eroare cod %d: (sql = %s) sau normal = ", cod, sqlite3_errstr(errno)); fflush(NULL); perror(0); break;
    }
    if(is_thread)
        pthread_exit(NULL);
    else
        exit(cod);
}

void init_sql(const char* db_filename)
{
    int rez;

    rez = sqlite3_open_v2(db_filename, &database, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, NULL);

    if(rez != SQLITE_OK)
    {
        if(database == NULL)
            handle_error(14);
        else
            handle_error(15, 0, sqlite3_errcode(database));
    }
    
    rez = sqlite3_exec(database, "PRAGMA foreign_keys = on;", NULL, NULL, NULL);
    if(rez != SQLITE_OK)
        handle_error(19, 0, sqlite3_errcode(database));
    
    sqlite3_stmt *create_users, *create_files, *create_access;
    
    rez = sqlite3_prepare_v2(database, "create table if not exists users (user_id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE, password TEXT);", -1, &create_users, NULL);
    if(rez != SQLITE_OK)
        handle_error(16, 0, sqlite3_errcode(database));

    rez = sqlite3_prepare_v2(database, "create table if not exists files (file_id INTEGER PRIMARY KEY, filename TEXT NOT NULL UNIQUE, contents TEXT, author INTEGER, is_public INTEGER DEFAULT 0, FOREIGN KEY(author) REFERENCES users(user_id));", -1, &create_files, NULL);
    if(rez != SQLITE_OK)
        handle_error(16, 0, sqlite3_errcode(database));

    rez = sqlite3_prepare_v2(database, "create table if not exists access (user_id INTEGER NOT NULL, file_id INTEGER NOT NULL, UNIQUE(user_id, file_id), FOREIGN KEY(user_id) REFERENCES users(user_id), FOREIGN KEY(file_id) REFERENCES files(file_id) ON DELETE CASCADE);", -1, &create_access, NULL);
    if(rez != SQLITE_OK)
        handle_error(16, 0, sqlite3_errcode(database));


    rez = sqlite3_step(create_users);
    if(rez != SQLITE_DONE)
        handle_error(17, 0, sqlite3_errcode(database));
    
    rez = sqlite3_step(create_files);
    if(rez != SQLITE_DONE)
        handle_error(17, 0, sqlite3_errcode(database));
    
    rez = sqlite3_step(create_access);
    if(rez != SQLITE_DONE)
        handle_error(17, 0, sqlite3_errcode(database));

    sqlite3_finalize(create_users); sqlite3_finalize(create_files); sqlite3_finalize(create_access);


    rez = sqlite3_prepare_v3(database, "select * from files;", -1, SQLITE_PREPARE_PERSISTENT, &list_files, NULL);
    if(rez != SQLITE_OK)
        handle_error(18, 0, sqlite3_errcode(database));
    
    rez = sqlite3_prepare_v3(database, "select * from files where filename = @filename;", -1, SQLITE_PREPARE_PERSISTENT, &get_file, NULL);
    if(rez != SQLITE_OK)
        handle_error(18, 0, sqlite3_errcode(database));
    
    rez = sqlite3_prepare_v3(database, "insert into files (filename, author) values (@filename, @author);", -1, SQLITE_PREPARE_PERSISTENT, &add_file, NULL);
    if(rez != SQLITE_OK)
        handle_error(18, 0, sqlite3_errcode(database));
    
    rez = sqlite3_prepare_v3(database, "update files set filename = @newname where file_id = @fileid", -1, SQLITE_PREPARE_PERSISTENT, &rename_file, NULL);
    if(rez != SQLITE_OK)
        handle_error(18, 0, sqlite3_errcode(database));
    
    rez = sqlite3_prepare_v3(database, "delete from files where file_id = @fileid;", -1, SQLITE_PREPARE_PERSISTENT, &delete_file, NULL);
    if(rez != SQLITE_OK)
        handle_error(18, 0, sqlite3_errcode(database));

    rez = sqlite3_prepare_v3(database, "update files set contents = @data where file_id = @fileid", -1, SQLITE_PREPARE_PERSISTENT, &update_contents, NULL);
    if(rez != SQLITE_OK)
        handle_error(18, 0, sqlite3_errcode(database));
    
    rez = sqlite3_prepare_v3(database, "insert into users (username, password) values (@username, @password);", -1, SQLITE_PREPARE_PERSISTENT, &add_user, NULL);
    if(rez != SQLITE_OK)
        handle_error(18, 0, sqlite3_errcode(database));
    
    rez = sqlite3_prepare_v3(database, "select * from users where username = @username", -1, SQLITE_PREPARE_PERSISTENT, &get_user, NULL);
    if(rez != SQLITE_OK)
        handle_error(18, 0, sqlite3_errcode(database));
    
    rez = sqlite3_prepare_v3(database, "select * from users where user_id = @userid", -1, SQLITE_PREPARE_PERSISTENT, &get_user_id, NULL);
    if(rez != SQLITE_OK)
        handle_error(18, 0, sqlite3_errcode(database));
    
    rez = sqlite3_prepare_v3(database, "insert into access values (@userid, @fileid);", -1, SQLITE_PREPARE_PERSISTENT, &allow_user_file, NULL);
    if(rez != SQLITE_OK)
        handle_error(18, 0, sqlite3_errcode(database));

    rez = sqlite3_prepare_v3(database, "delete from access where user_id = @userid and file_id = @fileid;", -1, SQLITE_PREPARE_PERSISTENT, &disallow_user_file, NULL);
    if(rez != SQLITE_OK)
        handle_error(18, 0, sqlite3_errcode(database));
    
    rez = sqlite3_prepare_v3(database, "update files set is_public = 1 where file_id = @fileid;", -1, SQLITE_PREPARE_PERSISTENT, &make_public, NULL);
    if(rez != SQLITE_OK)
        handle_error(18, 0, sqlite3_errcode(database));

    rez = sqlite3_prepare_v3(database, "update files set is_public = 0 where file_id = @fileid;", -1, SQLITE_PREPARE_PERSISTENT, &make_private, NULL);
    if(rez != SQLITE_OK)
        handle_error(18, 0, sqlite3_errcode(database));

    rez = sqlite3_prepare_v3(database, "select * from access where user_id = @userid and file_id = @fileid;", -1, SQLITE_PREPARE_PERSISTENT, &get_allowed, NULL);
    if(rez != SQLITE_OK)
        handle_error(18, 0, sqlite3_errcode(database));
}

int query_get_file(char* filename)
{
    sqlite3_reset(get_file);

    int rez;

    rez = sqlite3_bind_text(get_file, sqlite3_bind_parameter_index(get_file, "@filename"), filename, -1, SQLITE_STATIC);
    if(rez != SQLITE_OK) return rez;

    rez = sqlite3_step(get_file);
    return rez;
}

int query_get_user(char* username)
{
    sqlite3_reset(get_user);

    int rez;

    rez = sqlite3_bind_text(get_user, sqlite3_bind_parameter_index(get_user, "@username"), username, -1, SQLITE_STATIC);
    if(rez != SQLITE_OK) return rez;

    rez = sqlite3_step(get_user);
    return rez;
}

int query_get_user_id(int userid)
{
    sqlite3_reset(get_user_id);

    int rez;

    rez = sqlite3_bind_int(get_user_id, sqlite3_bind_parameter_index(get_user_id, "@userid"), userid);
    if(rez != SQLITE_OK) return rez;

    rez = sqlite3_step(get_user_id);
    return rez;
}

int query_get_allowed(int userid, int fileid)
{
    sqlite3_reset(get_allowed);

    int rez;

    rez = sqlite3_bind_int(get_allowed, sqlite3_bind_parameter_index(get_allowed, "@userid"), userid);
    if(rez != SQLITE_OK)
    {
        errno = sqlite3_errcode(database);
        pthread_mutex_unlock(&db_mutex);
        pthread_mutex_unlock(&file_modif_mutex);
        return 20;
    }

    rez = sqlite3_bind_int(get_allowed, sqlite3_bind_parameter_index(get_allowed, "@fileid"), fileid);
    if(rez != SQLITE_OK)
    {
        errno = sqlite3_errcode(database);
        pthread_mutex_unlock(&db_mutex);
        pthread_mutex_unlock(&file_modif_mutex);
        return 20;
    }

    rez = sqlite3_step(get_allowed);
    return rez;
}

int send_msg_socket(int sd, char *msg, int len, int type = 0) //type = 0 (string message), type = 1 (edit mode message)
{
    int sent = 0, target = sizeof(int);
    int rez;
    len += sizeof(int);
    int network_len = htonl(len);
    char* lenptr = (char*)(&network_len);
    while(sent < target)
    {
        rez = write(sd, lenptr+sent, target - sent);
        if (rez == -1)
            return 7;
        sent += rez;
    }
    sent = 0; target = sizeof(int);
    int network_type = htonl(type);
    char* typeptr = (char*)(&network_type);
    while(sent < target)
    {
        rez = write(sd, typeptr+sent, target - sent);
        if (rez == -1)
            return 7;
        sent += rez;        
    }
    len -= sizeof(int);
    sent = 0;
    target = len;
    while (sent < target)
    {
        rez = write(sd, msg + sent, target - sent);
        if (rez == -1)
            return 7;
        sent += rez;
    }
    return 0;
}

int receive_msg_socket(int sd, char* &out, int &len)
{
    int received = 0, target = sizeof(int);
    int rez;
    int network_len;
    char* lenptr = (char*)(&network_len);
    while(received < target)
    {
        rez = read(sd, lenptr+received, target - received);
        if(rez == -1)
            return 9;
        if(rez == 0)
            return 10;
        received += rez;
    }
    len = ntohl(network_len);

    out = (char*)malloc(len+1);
    if(out == NULL)
        return 11;

    received = 0; target = len;
    while(received < target)
    {
        rez = read(sd, out+received, target - received);
        if(rez == -1)
        {
            free(out);
            return 9;
        }
        if(rez == 0)
        {
            free(out);
            return 10;
        }
        received += rez;
    }
    out[len] = 0;
    return 0;
}

int handle_login(thread_info &data, char* msg, int msglen, std::string &out)
{
    int rez;
    char* saveptr = NULL;
    char* cmd, *user, *pass, *test;
    cmd = strtok_r(msg, " ", &saveptr);
    user = strtok_r(NULL, " ", &saveptr);
    pass = strtok_r(NULL, " ", &saveptr);
    test = strtok_r(NULL, " ", &saveptr);
    if(user == NULL || pass == NULL || test != NULL)
    {
        out = "Eroare: utilizare incorecta. Format: login <user> <pass>";
        return 0;
    }

    if(data.logged_in)
    {
        out = "Eroare: Comanda nu poate fi executata cat timp esti logat.";
        return 0;
    }

    pthread_mutex_lock(&db_mutex);

    rez = query_get_user(user);
    if(rez == SQLITE_DONE)
    {
        pthread_mutex_unlock(&db_mutex);
        out = "Nu exista user inregistrat cu username-ul specificat.";
        return 0;
    }
    if(rez != SQLITE_ROW)
    {
        errno = sqlite3_errcode(database);
        pthread_mutex_unlock(&db_mutex);
        return 21;
    }

    const unsigned char* password = sqlite3_column_text(get_user, 2);

    if(strcmp(pass, (const char*)password) != 0)
    {
        pthread_mutex_unlock(&db_mutex);
        out = "Parola incorecta.";
        return 0;
    }

    data.logged_user_id = sqlite3_column_int(get_user, 0);
    data.logged_username = user;
    data.logged_in = 1;

    pthread_mutex_unlock(&db_mutex);
    
    out = "Autentificat.";

    return 0;
}

int handle_register(thread_info &data, char* msg, int msglen, std::string &out)
{
    int rez;
    char* saveptr = NULL;
    char* cmd, *user, *pass, *test;
    cmd = strtok_r(msg, " ", &saveptr);
    user = strtok_r(NULL, " ", &saveptr);
    pass = strtok_r(NULL, " ", &saveptr);
    test = strtok_r(NULL, " ", &saveptr);
    if(user == NULL || pass == NULL || test != NULL)
    {
        out = "Eroare: utilizare incorecta. Format: register <user> <pass>";
        return 0;
    }

    if(data.logged_in)
    {
        out = "Eroare: Comanda nu poate fi executata cat timp esti logat.";
        return 0;
    }

    pthread_mutex_lock(&db_mutex);

    sqlite3_reset(add_user);

    rez = sqlite3_bind_text(add_user, sqlite3_bind_parameter_index(add_user, "@username"), user, -1, SQLITE_STATIC);
    if(rez != SQLITE_OK)
    {
        errno = sqlite3_errcode(database);
        pthread_mutex_unlock(&db_mutex);
        return 20;
    }

    rez = sqlite3_bind_text(add_user, sqlite3_bind_parameter_index(add_user, "@password"), pass, -1, SQLITE_STATIC);
    if(rez != SQLITE_OK)
    {
        errno = sqlite3_errcode(database);
        pthread_mutex_unlock(&db_mutex);
        return 20;
    }

    rez = sqlite3_step(add_user);
    if(rez == SQLITE_CONSTRAINT)
    {
        pthread_mutex_unlock(&db_mutex);
        out = "Exista deja user inregistrat cu username-ul specificat.";
        return 0;
    }
    if(rez != SQLITE_DONE)
    {
        errno = sqlite3_errcode(database);
        pthread_mutex_unlock(&db_mutex);
        return 21;
    }

    pthread_mutex_unlock(&db_mutex);
    
    out = "Inregistrat.";
    return 0;
}

int handle_logout(thread_info &data, char* msg, int msglen, std::string &out)
{
    int rez;
    char *saveptr;
    char* cmd, *test;
    cmd = strtok_r(msg, " ", &saveptr);
    test = strtok_r(NULL, " ", &saveptr);
    
    if(test != NULL)
    {
        out = "Eroare: utilizare incorecta. Format: logout";
        return 0;
    }

    if(!data.logged_in)
    {
        out = "Nu esti logat.";
        return 0;
    }
    
    data.logged_user_id = 0;
    data.logged_username.clear();
    data.logged_in = 0;

    out = "Ai fost delogat.";

    return 0;
}

int check_filename(const char* name)
{
    for(int i = 0; name[i] != 0; i++)
        if(!check_accepted(name[i]) || name[i] == '\\' || name[i] == '/')
            return 0;

    if(strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
        return 0;
    return 1;
}

int handle_create_file(thread_info &data, char* msg, int msglen, std::string &out)
{
    int rez;
    char *saveptr;
    char* cmd, *filename, *test;
    cmd = strtok_r(msg, " ", &saveptr);
    filename = strtok_r(NULL, " ", &saveptr);
    test = strtok_r(NULL, " ", &saveptr);
    if(filename == NULL || test != NULL)
    {
        out = "Eroare: utilizare incorecta. Format: create_file <filename>";
        return 0;
    }
    
    if(!data.logged_in)
    {
        out = "Nu esti logat.";
        return 0;
    }

    if(!check_filename(filename))
    {
        out = "Numele cerut pentru fisier nu este permis.";
        return 0;
    }

    pthread_mutex_lock(&file_modif_mutex);
    pthread_mutex_lock(&db_mutex);

    sqlite3_reset(add_file);

    rez = sqlite3_bind_text(add_file, sqlite3_bind_parameter_index(add_file, "@filename"), filename, -1, SQLITE_STATIC);
    if(rez != SQLITE_OK)
    {
        errno = sqlite3_errcode(database);
        pthread_mutex_unlock(&db_mutex);
        pthread_mutex_unlock(&file_modif_mutex);
        return 20;
    }

    rez = sqlite3_bind_int(add_file, sqlite3_bind_parameter_index(add_file, "@author"), data.logged_user_id);
    if(rez != SQLITE_OK)
    {
        errno = sqlite3_errcode(database);
        pthread_mutex_unlock(&db_mutex);
        pthread_mutex_unlock(&file_modif_mutex);
        return 20;
    }

    rez = sqlite3_step(add_file);
    if(rez == SQLITE_CONSTRAINT)
    {
        pthread_mutex_unlock(&db_mutex);
        pthread_mutex_unlock(&file_modif_mutex);
        out = "Exista deja fisier cu numele specificat.";
        return 0;
    }
    if(rez != SQLITE_DONE)
    {
        errno = sqlite3_errcode(database);
        pthread_mutex_unlock(&db_mutex);
        pthread_mutex_unlock(&file_modif_mutex);
        return 21;
    }

    pthread_mutex_unlock(&db_mutex);
    pthread_mutex_unlock(&file_modif_mutex);
    out = "Fisier creat.";

    return 0;
}

int handle_rename_file(thread_info &data, char* msg, int msglen, std::string &out)
{
    int rez;
    char *saveptr;
    char* cmd, *filename, *newname, *test;
    cmd = strtok_r(msg, " ", &saveptr);
    filename = strtok_r(NULL, " ", &saveptr);
    newname = strtok_r(NULL, " ", &saveptr);
    test = strtok_r(NULL, " ", &saveptr);
    if(filename == NULL || newname == NULL || test != NULL)
    {
        out = "Eroare: utilizare incorecta. Format: rename_file <oldfilename> <newfilename>";
        return 0;
    }
    
    if(!data.logged_in)
    {
        out = "Nu esti logat.";
        return 0;
    }

    if(!check_filename(filename))
    {
        out = "Numele cerut pentru fisier nu este permis.";
        return 0;
    }

    if(strcmp(filename, newname) == 0)
    {
        out = "Numele initial si cel finial sunt identice.";
        return 0;
    }

    pthread_mutex_lock(&file_modif_mutex);
    pthread_mutex_lock(&db_mutex);

    rez = query_get_file(filename);
    if(rez == SQLITE_DONE)
    {
        pthread_mutex_unlock(&db_mutex);
        pthread_mutex_unlock(&file_modif_mutex);
        out = "Nu exista fisier cu numele dat.";
        return 0;
    }

    if(rez != SQLITE_ROW)
    {
        errno = sqlite3_errcode(database);
        pthread_mutex_unlock(&db_mutex);
        pthread_mutex_unlock(&file_modif_mutex);
        return 21;
    }

    int author = sqlite3_column_int(get_file, 3);

    if(author != data.logged_user_id)
    {
        pthread_mutex_unlock(&db_mutex);
        pthread_mutex_unlock(&file_modif_mutex);
        out = "Nu ai permisiune sa schimbi numele fisierului cerut.";
        return 0;
    }

    int fileid = sqlite3_column_int(get_file, 0);

    pthread_mutex_unlock(&db_mutex);

    int is_opened = 0;
    file_info* open_file;

    pthread_mutex_lock(&map_mutex);

    if(open_files.count(filename) == 1)
    {
        is_opened = 1;
        open_file = open_files[filename];

        pthread_mutex_lock(&open_file->access_mutex);

        if(open_file->connected[0])
        {
            pthread_mutex_unlock(&open_file->access_mutex);
            pthread_mutex_unlock(&map_mutex);
            pthread_mutex_unlock(&file_modif_mutex);

            out = "Fisierul nu poate fi redenumit caci momentan este deschis pentru editare.";
            return 0;
        }
    }
    else
    {
        pthread_mutex_unlock(&map_mutex);
    }

    pthread_mutex_lock(&db_mutex);

    sqlite3_reset(rename_file);

    rez = sqlite3_bind_text(rename_file, sqlite3_bind_parameter_index(rename_file, "@newname"), newname, -1, SQLITE_STATIC);
    if(rez != SQLITE_OK)
    {
        errno = sqlite3_errcode(database);
        pthread_mutex_unlock(&db_mutex);

        if(is_opened)
        {
            pthread_mutex_unlock(&open_file->access_mutex);
            pthread_mutex_unlock(&map_mutex);
        }
        
        pthread_mutex_unlock(&file_modif_mutex);
        return 20;
    }

    rez = sqlite3_bind_int(rename_file, sqlite3_bind_parameter_index(rename_file, "@fileid"), fileid);
    if(rez != SQLITE_OK)
    {
        errno = sqlite3_errcode(database);
        pthread_mutex_unlock(&db_mutex);

        if(is_opened)
        {
            pthread_mutex_unlock(&open_file->access_mutex);
            pthread_mutex_unlock(&map_mutex);
        }
        
        pthread_mutex_unlock(&file_modif_mutex);
        return 20;
    }

    rez = sqlite3_step(rename_file);
    if(rez == SQLITE_CONSTRAINT)
    {
        if(is_opened)
        {
            pthread_mutex_unlock(&open_file->access_mutex);
            pthread_mutex_unlock(&map_mutex);
        }
        pthread_mutex_unlock(&db_mutex);
        pthread_mutex_unlock(&file_modif_mutex);
        out = "Exista deja fisier cu numele specificat.";
        return 0;
    }
    if(rez != SQLITE_DONE)
    {
        errno = sqlite3_errcode(database);
        pthread_mutex_unlock(&db_mutex);

        if(is_opened)
        {
            pthread_mutex_unlock(&open_file->access_mutex);
            pthread_mutex_unlock(&map_mutex);
        }
        
        pthread_mutex_unlock(&file_modif_mutex);
        return 21;
    }

    pthread_mutex_unlock(&db_mutex);

    if(is_opened)
    {
        open_file->data.filename = newname;
        open_files.erase(filename);
        open_files[newname] = open_file;

        pthread_mutex_unlock(&open_file->access_mutex);
        pthread_mutex_unlock(&map_mutex);
    }


    pthread_mutex_unlock(&file_modif_mutex);


    out = "Fisier redenumit.";

    return 0;
}

int handle_delete_file(thread_info &data, char* msg, int msglen, std::string &out)
{
    int rez;
    char *saveptr;
    char* cmd, *filename, *test;
    cmd = strtok_r(msg, " ", &saveptr);
    filename = strtok_r(NULL, " ", &saveptr);
    test = strtok_r(NULL, " ", &saveptr);
    if(filename == NULL || test != NULL)
    {
        out = "Eroare: utilizare incorecta. Format: delete_file <filename>";
        return 0;
    }
        
    if(!data.logged_in)
    {
        out = "Nu esti logat.";
        return 0;
    }

    pthread_mutex_lock(&file_modif_mutex);
    pthread_mutex_lock(&db_mutex);

    rez = query_get_file(filename);
    if(rez == SQLITE_DONE)
    {
        pthread_mutex_unlock(&db_mutex);
        pthread_mutex_unlock(&file_modif_mutex);
        out = "Nu exista fisier cu numele dat.";
        return 0;
    }

    if(rez != SQLITE_ROW)
    {
        errno = sqlite3_errcode(database);
        pthread_mutex_unlock(&db_mutex);
        pthread_mutex_unlock(&file_modif_mutex);
        return 21;
    }

    int author = sqlite3_column_int(get_file, 3);

    if(author != data.logged_user_id)
    {
        pthread_mutex_unlock(&db_mutex);
        pthread_mutex_unlock(&file_modif_mutex);
        out = "Nu ai permisiune sa stergi fisierului cerut.";
        return 0;
    }

    int fileid = sqlite3_column_int(get_file, 0);

    pthread_mutex_unlock(&db_mutex);

    int is_opened = 0;
    file_info* open_file;

    pthread_mutex_lock(&map_mutex);

    if(open_files.count(filename) == 1)
    {
        is_opened = 1;
        open_file = open_files[filename];

        pthread_mutex_lock(&open_file->access_mutex);

        if(open_file->connected[0])
        {
            pthread_mutex_unlock(&open_file->access_mutex);
            pthread_mutex_unlock(&map_mutex);
            pthread_mutex_unlock(&file_modif_mutex);

            out = "Fisierul nu poate fi sters caci momentan este deschis pentru editare.";
            return 0;
        }
    }
    else
    {
        pthread_mutex_unlock(&map_mutex);
    }

    pthread_mutex_lock(&db_mutex);

    sqlite3_reset(delete_file);

    rez = sqlite3_bind_int(delete_file, sqlite3_bind_parameter_index(delete_file, "@fileid"), fileid);
    if(rez != SQLITE_OK)
    {
        errno = sqlite3_errcode(database);
        pthread_mutex_unlock(&db_mutex);
        
        if(is_opened)
        {
            pthread_mutex_unlock(&open_file->access_mutex);
            pthread_mutex_unlock(&map_mutex);
        }
        
        pthread_mutex_unlock(&file_modif_mutex);
        return 20;
    }

    rez = sqlite3_step(delete_file);
    if(rez != SQLITE_DONE)
    {
        errno = sqlite3_errcode(database);
        pthread_mutex_unlock(&db_mutex);

        if(is_opened)
        {
            pthread_mutex_unlock(&open_file->access_mutex);
            pthread_mutex_unlock(&map_mutex);
        }
        
        pthread_mutex_unlock(&file_modif_mutex);
        return 21;
    }

    pthread_mutex_unlock(&db_mutex);

    if(is_opened)
    {
        pthread_mutex_unlock(&open_file->access_mutex);
        open_files.erase(filename);

        open_file->~file_info();
        free(open_file);

        pthread_mutex_unlock(&map_mutex);
    }

    pthread_mutex_unlock(&file_modif_mutex);

    out = "Fisier sters.";
    
    return 0;
}

int handle_allow(thread_info &data, char* msg, int msglen, std::string &out)
{
    int rez;
    char *saveptr;
    char* cmd, *filename, *user, *test;
    cmd = strtok_r(msg, " ", &saveptr);
    filename = strtok_r(NULL, " ", &saveptr);
    user = strtok_r(NULL, " ", &saveptr);
    test = strtok_r(NULL, " ", &saveptr);
    if(filename == NULL || user == NULL || test != NULL)
    {
        out = "Eroare: utilizare incorecta. Format: allow <filename> <user>";
        return 0;
    }

    if(!data.logged_in)
    {
        out = "Nu esti logat.";
        return 0;
    }
    
    pthread_mutex_lock(&file_modif_mutex);
    pthread_mutex_lock(&db_mutex);

    rez = query_get_file(filename);
    if(rez == SQLITE_DONE)
    {
        pthread_mutex_unlock(&db_mutex);
        pthread_mutex_unlock(&file_modif_mutex);
        out = "Nu exista fisier cu numele dat.";
        return 0;
    }

    if(rez != SQLITE_ROW)
    {
        errno = sqlite3_errcode(database);
        pthread_mutex_unlock(&db_mutex);
        pthread_mutex_unlock(&file_modif_mutex);
        return 21;
    }

    int author = sqlite3_column_int(get_file, 3);
    if(author != data.logged_user_id)
    {
        pthread_mutex_unlock(&db_mutex);
        pthread_mutex_unlock(&file_modif_mutex);
        out = "Nu poti acorda acces altora la fisierul cerut.";
        return 0;
    }

    int fileid = sqlite3_column_int(get_file, 0);

    rez = query_get_user(user);
    if(rez == SQLITE_DONE)
    {
        pthread_mutex_unlock(&db_mutex);
        pthread_mutex_unlock(&file_modif_mutex);
        out = "Nu exista user cu username-ul dat.";
        return 0;
    }

    if(rez != SQLITE_ROW)
    {
        errno = sqlite3_errcode(database);
        pthread_mutex_unlock(&db_mutex);
        pthread_mutex_unlock(&file_modif_mutex);
        return 21;
    }

    int userid = sqlite3_column_int(get_user, 0);

    if(userid == data.logged_user_id)
    {
        pthread_mutex_unlock(&db_mutex);
        pthread_mutex_unlock(&file_modif_mutex);
        out = "Nu iti poti acorda permisiune singur la un fisier creat de tine.";
        return 0;
    }

    sqlite3_reset(allow_user_file);

    rez = sqlite3_bind_int(allow_user_file, sqlite3_bind_parameter_index(allow_user_file, "@userid"), userid);
    if(rez != SQLITE_OK)
    {
        errno = sqlite3_errcode(database);
        pthread_mutex_unlock(&db_mutex);
        pthread_mutex_unlock(&file_modif_mutex);
        return 20;
    }

    rez = sqlite3_bind_int(allow_user_file, sqlite3_bind_parameter_index(allow_user_file, "@fileid"), fileid);
    if(rez != SQLITE_OK)
    {
        errno = sqlite3_errcode(database);
        pthread_mutex_unlock(&db_mutex);
        pthread_mutex_unlock(&file_modif_mutex);
        return 20;
    }

    rez = sqlite3_step(allow_user_file);
    if(rez == SQLITE_CONSTRAINT)
    {
        pthread_mutex_unlock(&db_mutex);
        pthread_mutex_unlock(&file_modif_mutex);
        out = "Ai acordat deja permisiune acestui user pentru acest fisier.";
        return 0;
    }
    if(rez != SQLITE_DONE)
    {
        errno = sqlite3_errcode(database);
        pthread_mutex_unlock(&db_mutex);
        pthread_mutex_unlock(&file_modif_mutex);
        return 21;
    }

    pthread_mutex_unlock(&db_mutex);
    pthread_mutex_unlock(&file_modif_mutex);
    
    out = "Permisiune de editare acordata.";
    return 0;
}

int handle_disallow(thread_info &data, char* msg, int msglen, std::string &out)
{
    int rez;
    char *saveptr;
    char* cmd, *filename, *user, *test;
    cmd = strtok_r(msg, " ", &saveptr);
    filename = strtok_r(NULL, " ", &saveptr);
    user = strtok_r(NULL, " ", &saveptr);
    test = strtok_r(NULL, " ", &saveptr);
    if(filename == NULL || user == NULL || test != NULL)
    {
        out = "Eroare: utilizare incorecta. Format: disallow <filename> <user>";
        return 0;
    }

    if(!data.logged_in)
    {
        out = "Nu esti logat.";
        return 0;
    }
    
    pthread_mutex_lock(&file_modif_mutex);
    pthread_mutex_lock(&db_mutex);

    rez = query_get_file(filename);
    if(rez == SQLITE_DONE)
    {
        pthread_mutex_unlock(&db_mutex);
        pthread_mutex_unlock(&file_modif_mutex);
        out = "Nu exista fisier cu numele dat.";
        return 0;
    }

    if(rez != SQLITE_ROW)
    {
        errno = sqlite3_errcode(database);
        pthread_mutex_unlock(&db_mutex);
        pthread_mutex_unlock(&file_modif_mutex);
        return 21;
    }

    int author = sqlite3_column_int(get_file, 3);
    if(author != data.logged_user_id)
    {
        pthread_mutex_unlock(&db_mutex);
        pthread_mutex_unlock(&file_modif_mutex);
        out = "Nu poti bloca accesul altora la fisierul cerut.";
        return 0;
    }

    int fileid = sqlite3_column_int(get_file, 0);

    rez = query_get_user(user);
    if(rez == SQLITE_DONE)
    {
        pthread_mutex_unlock(&db_mutex);
        pthread_mutex_unlock(&file_modif_mutex);
        out = "Nu exista user cu username-ul dat.";
        return 0;
    }

    if(rez != SQLITE_ROW)
    {
        errno = sqlite3_errcode(database);
        pthread_mutex_unlock(&db_mutex);
        pthread_mutex_unlock(&file_modif_mutex);
        return 21;
    }

    int userid = sqlite3_column_int(get_user, 0);

    if(userid == data.logged_user_id)
    {
        pthread_mutex_unlock(&db_mutex);
        pthread_mutex_unlock(&file_modif_mutex);
        out = "Nu iti poti revoca permisiune singur la un fisier creat de tine.";
        return 0;
    }

    sqlite3_reset(disallow_user_file);

    rez = sqlite3_bind_int(disallow_user_file, sqlite3_bind_parameter_index(disallow_user_file, "@userid"), userid);
    if(rez != SQLITE_OK)
    {
        errno = sqlite3_errcode(database);
        pthread_mutex_unlock(&db_mutex);
        pthread_mutex_unlock(&file_modif_mutex);
        return 20;
    }

    rez = sqlite3_bind_int(disallow_user_file, sqlite3_bind_parameter_index(disallow_user_file, "@fileid"), fileid);
    if(rez != SQLITE_OK)
    {
        errno = sqlite3_errcode(database);
        pthread_mutex_unlock(&db_mutex);
        pthread_mutex_unlock(&file_modif_mutex);
        return 20;
    }

    rez = sqlite3_step(disallow_user_file);
    if(rez != SQLITE_DONE)
    {
        errno = sqlite3_errcode(database);
        pthread_mutex_unlock(&db_mutex);
        pthread_mutex_unlock(&file_modif_mutex);
        return 21;
    }

    pthread_mutex_unlock(&db_mutex);
    pthread_mutex_unlock(&file_modif_mutex);
    
    out = "Permisiune de editare revocata.";
    return 0;
}

int handle_public(thread_info &data, char* msg, int msglen, std::string &out)
{
    int rez;
    char *saveptr;
    char* cmd, *filename, *test;
    cmd = strtok_r(msg, " ", &saveptr);
    filename = strtok_r(NULL, " ", &saveptr);
    test = strtok_r(NULL, " ", &saveptr);
    if(filename == NULL || test != NULL)
    {
        out = "Eroare: utilizare incorecta. Format: make_public <filename>";
        return 0;
    }

    if(!data.logged_in)
    {
        out = "Nu esti logat.";
        return 0;
    }
    
    pthread_mutex_lock(&file_modif_mutex);
    pthread_mutex_lock(&db_mutex);

    rez = query_get_file(filename);
    if(rez == SQLITE_DONE)
    {
        pthread_mutex_unlock(&db_mutex);
        pthread_mutex_unlock(&file_modif_mutex);
        out = "Nu exista fisier cu numele dat.";
        return 0;
    }

    if(rez != SQLITE_ROW)
    {
        errno = sqlite3_errcode(database);
        pthread_mutex_unlock(&db_mutex);
        pthread_mutex_unlock(&file_modif_mutex);
        return 21;
    }

    int author = sqlite3_column_int(get_file, 3);
    if(author != data.logged_user_id)
    {
        pthread_mutex_unlock(&db_mutex);
        pthread_mutex_unlock(&file_modif_mutex);
        out = "Nu poti face fisierul cerut public.";
        return 0;
    }

    int fileid = sqlite3_column_int(get_file, 0);

    sqlite3_reset(make_public);

    rez = sqlite3_bind_int(make_public, sqlite3_bind_parameter_index(make_public, "@fileid"), fileid);
    if(rez != SQLITE_OK)
    {
        errno = sqlite3_errcode(database);
        pthread_mutex_unlock(&db_mutex);
        pthread_mutex_unlock(&file_modif_mutex);
        return 20;
    }

    rez = sqlite3_step(make_public);
    if(rez != SQLITE_DONE)
    {
        errno = sqlite3_errcode(database);
        pthread_mutex_unlock(&db_mutex);
        pthread_mutex_unlock(&file_modif_mutex);
        return 21;
    }

    pthread_mutex_unlock(&db_mutex);
    pthread_mutex_unlock(&file_modif_mutex);
    
    out = "Fisierul a fost marcat drept public (pentru editare, download).";
    return 0;
}

int handle_private(thread_info &data, char* msg, int msglen, std::string &out)
{
    int rez;
    char *saveptr;
    char* cmd, *filename, *test;
    cmd = strtok_r(msg, " ", &saveptr);
    filename = strtok_r(NULL, " ", &saveptr);
    test = strtok_r(NULL, " ", &saveptr);
    if(filename == NULL || test != NULL)
    {
        out = "Eroare: utilizare incorecta. Format: make_private <filename>";
        return 0;
    }

    if(!data.logged_in)
    {
        out = "Nu esti logat.";
        return 0;
    }
    
    pthread_mutex_lock(&file_modif_mutex);
    pthread_mutex_lock(&db_mutex);

    rez = query_get_file(filename);
    if(rez == SQLITE_DONE)
    {
        pthread_mutex_unlock(&db_mutex);
        pthread_mutex_unlock(&file_modif_mutex);
        out = "Nu exista fisier cu numele dat.";
        return 0;
    }

    if(rez != SQLITE_ROW)
    {
        errno = sqlite3_errcode(database);
        pthread_mutex_unlock(&db_mutex);
        pthread_mutex_unlock(&file_modif_mutex);
        return 21;
    }

    int author = sqlite3_column_int(get_file, 3);
    if(author != data.logged_user_id)
    {
        pthread_mutex_unlock(&db_mutex);
        pthread_mutex_unlock(&file_modif_mutex);
        out = "Nu poti face fisierul cerut privat.";
        return 0;
    }

    int fileid = sqlite3_column_int(get_file, 0);

    sqlite3_reset(make_private);

    rez = sqlite3_bind_int(make_private, sqlite3_bind_parameter_index(make_private, "@fileid"), fileid);
    if(rez != SQLITE_OK)
    {
        errno = sqlite3_errcode(database);
        pthread_mutex_unlock(&db_mutex);
        pthread_mutex_unlock(&file_modif_mutex);
        return 20;
    }

    rez = sqlite3_step(make_private);
    if(rez != SQLITE_DONE)
    {
        errno = sqlite3_errcode(database);
        pthread_mutex_unlock(&db_mutex);
        pthread_mutex_unlock(&file_modif_mutex);
        return 21;
    }

    pthread_mutex_unlock(&db_mutex);
    pthread_mutex_unlock(&file_modif_mutex);
    
    out = "Fisierul a fost marcat drept privat (pentru editare, download).";
    return 0;
}

int handle_list(thread_info &data, char* msg, int msglen, std::string &out)
{
    int rez;
    char *saveptr;
    char* cmd, *test;
    cmd = strtok_r(msg, " ", &saveptr);
    test = strtok_r(NULL, " ", &saveptr);
    if(test != NULL)
    {
        out = "Eroare: utilizare incorecta. Format: list";
        return 0;
    }
    
    if(!data.logged_in)
    {
        out = "Nu esti logat.";
        return 0;
    }

    out = "";

    pthread_mutex_lock(&file_modif_mutex);
    pthread_mutex_lock(&db_mutex);

    sqlite3_reset(list_files);

    int is_first_row = 1;
    rez = sqlite3_step(list_files);
    while(rez == SQLITE_ROW)
    {
        std::string filename = (const char*)sqlite3_column_text(list_files, 1);
        int authorid = sqlite3_column_int(list_files, 3);
        int is_public = sqlite3_column_int(list_files, 4);

        rez = query_get_user_id(authorid);
        if(rez == SQLITE_DONE)
        {
            pthread_mutex_unlock(&db_mutex);
            pthread_mutex_unlock(&file_modif_mutex);
            return 25;
        }
        if(rez != SQLITE_ROW)
        {
            errno = sqlite3_errcode(database);
            pthread_mutex_unlock(&db_mutex);
            pthread_mutex_unlock(&file_modif_mutex);
            return 21;
        }

        std::string username = (const char*)sqlite3_column_text(get_user_id, 1);

        if(!is_first_row)
            out += "\n";

        out += filename + " -- author = " + username + " -- " + (is_public ? "public" : "private");

        is_first_row = 0;
        rez = sqlite3_step(list_files);
    }

    if(rez != SQLITE_DONE)
    {
        errno = sqlite3_errcode(database);
        pthread_mutex_unlock(&db_mutex);
        pthread_mutex_unlock(&file_modif_mutex);
        return 21;
    }

    pthread_mutex_unlock(&db_mutex);
    pthread_mutex_unlock(&file_modif_mutex);

    if(is_first_row)
        out = "Nu exista fisiere pe server.";

    return 0;
}

int save_file_in_db(thread_info &data)
{
    int rez;

    char* filestr = (char*)malloc(data.edited_file->data.size+1);
    rez = convert_to_str(data.edited_file->data.lines, filestr);
    if(rez != 0)
    {
        free(filestr);
        return rez;
    }
    filestr[data.edited_file->data.size] = 0;

    sqlite3_reset(update_contents);

    rez = sqlite3_bind_text(update_contents, sqlite3_bind_parameter_index(update_contents, "@data"), filestr, data.edited_file->data.size, SQLITE_STATIC);
    if(rez != 0)
    {
        free(filestr);
        return 20;
    }

    rez = sqlite3_bind_int(update_contents, sqlite3_bind_parameter_index(update_contents, "@fileid"), data.edited_file->fileid);
    if(rez != 0)
    {
        free(filestr);
        return 20;
    }

    rez = sqlite3_step(update_contents);
    if(rez != SQLITE_DONE)
    {
        free(filestr);
        return 21;
    }

    free(filestr);
    return 0;
}

int prepare_edit_msg_srv_client(edit_act_srv_client act, int filelen, char* &out, int &outlen)
{
    int len = sizeof(int);
    switch(act)
    {
        case edit_deny:
        case edit_accept:
        {
            break;
        }
        case edit_filename:
        case edit_data:
        {
            len += filelen;
            break;
        }
        case edit_cursors:
        {
            len += 2*sizeof(file_cursor);
            break;    
        }
        case edit_conn:
        {
            len += sizeof(int) + sizeof(file_cursor);
            break;
        }
        case edit_disconn:
        case edit_backspace:
        case edit_tab:
        {
            len += sizeof(int);
            break;
        }
        case edit_char:
        case edit_arrow:
        {
            len += sizeof(int) + 1;
            break;
        }
        default: return 13;
    }

    out = (char*)malloc(len);
    if(out == NULL) 
        return 11;

    *((int*)out) = htonl((int)act);
    outlen = len;
    return 0;
}


int handle_download(thread_info &data, char* msg, int msglen, std::string &out)
{
    int rez;
    char *saveptr;
    char* cmd, *filename, *test;
    cmd = strtok_r(msg, " ", &saveptr);
    filename = strtok_r(NULL, " ", &saveptr);
    test = strtok_r(NULL, " ", &saveptr);
    if(filename == NULL || test != NULL)
    {
        out = "Eroare: utilizare incorecta. Format: download <filename>";
        return 0;
    }
    
    if(!data.logged_in)
    {
        out = "Nu esti logat.";
        return 0;
    }

    pthread_mutex_lock(&file_modif_mutex);
    pthread_mutex_lock(&db_mutex);

    rez = query_get_file(filename);
    if(rez == SQLITE_DONE)
    {
        pthread_mutex_unlock(&db_mutex);
        pthread_mutex_unlock(&file_modif_mutex);
        out = "Nu exista fisier cu numele dat.";
        return 0;
    }

    if(rez != SQLITE_ROW)
    {
        errno = sqlite3_errcode(database);
        pthread_mutex_unlock(&db_mutex);
        pthread_mutex_unlock(&file_modif_mutex);
        return 21;
    }

    int fileid = sqlite3_column_int(get_file, 0);
    int author = sqlite3_column_int(get_file, 3);
    int is_public = sqlite3_column_int(get_file, 4);

    if(!is_public && author != data.logged_user_id)
    {
        rez = query_get_allowed(data.logged_user_id, fileid);
        if(rez == SQLITE_DONE)
        {
            pthread_mutex_unlock(&db_mutex);
            pthread_mutex_unlock(&file_modif_mutex);
            out = "Nu ai permisiune de a descarca fisierul cerut.";
            return 0;
        }
        if(rez != SQLITE_ROW)
        {
            errno = sqlite3_errcode(database);
            pthread_mutex_unlock(&db_mutex);
            pthread_mutex_unlock(&file_modif_mutex);
            return 21;
        }
    }

    const char* contents = (const char *)sqlite3_column_text(get_file, 2);
    if(contents == NULL)
    {
        if(sqlite3_errcode(database) != SQLITE_ROW)
        {
            errno = sqlite3_errcode(database);
            pthread_mutex_unlock(&db_mutex);
            pthread_mutex_unlock(&file_modif_mutex);
            return 23;
        }

        contents = "";
    }

    char* response = NULL;
    int responselen = 0;
    rez = prepare_edit_msg_srv_client(edit_accept, 0, response, responselen);
    if(rez != 0)
    {
        pthread_mutex_unlock(&db_mutex);
        pthread_mutex_unlock(&file_modif_mutex);
        return rez;
    }

    rez = send_msg_socket(data.client_sd, response, responselen, 1);
    free(response);
    if(rez != 0)
    {
        pthread_mutex_unlock(&db_mutex);
        pthread_mutex_unlock(&file_modif_mutex);
        return rez;
    }
    
    rez = prepare_edit_msg_srv_client(edit_filename, strlen(filename), response, responselen);
    if(rez != 0)
    {
        pthread_mutex_unlock(&db_mutex);
        pthread_mutex_unlock(&file_modif_mutex);
        return rez;
    }

    strncpy(response+sizeof(int), filename, strlen(filename));
    rez = send_msg_socket(data.client_sd, response, responselen, 1);
    free(response);
    if(rez != 0)
    {
        pthread_mutex_unlock(&db_mutex);
        pthread_mutex_unlock(&file_modif_mutex);
        return rez;
    }

    int filelen = strlen(contents);
    rez = prepare_edit_msg_srv_client(edit_data, filelen, response, responselen);
    if(rez != 0)
    {
        pthread_mutex_unlock(&db_mutex);
        pthread_mutex_unlock(&file_modif_mutex);
        return rez;
    }

    strncpy(response+sizeof(int), contents, filelen);

    rez = send_msg_socket(data.client_sd, response, responselen, 1);
    free(response);
    if(rez != 0)
    {
        pthread_mutex_unlock(&db_mutex);
        pthread_mutex_unlock(&file_modif_mutex);
        return rez;
    }

    pthread_mutex_unlock(&db_mutex);
    pthread_mutex_unlock(&file_modif_mutex);

    out = "";
    return 0;
}

void send_to_clients(thread_info &data, char* msg, int msglen, int (&succ)[2])
{
    if(data.edited_file->connected[0] && data.edited_file->client[0] != -1)
        succ[0] = send_msg_socket(data.edited_file->client[0], msg, msglen, 1);
    if(data.edited_file->connected[1] && data.edited_file->client[1] != -1)
        succ[1] = send_msg_socket(data.edited_file->client[1], msg, msglen, 1);
}

int connect_client(thread_info &data, char* filename)
{
    int rez, sd = data.client_sd;
    file_info *info = data.edited_file;
    if(info->initialized == 0)
    {
        pthread_mutex_lock(&db_mutex);
        
        const char* contents = (const char*)sqlite3_column_text(get_file, 2);

        load_file(info->data, contents);
        
        info->initialized = 1;
        pthread_mutex_unlock(&db_mutex);
    }

    char* response = NULL;
    int responselen = 0;
    rez = prepare_edit_msg_srv_client(edit_accept, 0, response, responselen);
    if(rez != 0)
        return rez;

    rez = send_msg_socket(sd, response, responselen, 1);
    free(response);
    if(rez != 0)
        return rez;
    
    rez = prepare_edit_msg_srv_client(edit_filename, info->data.filename.length(), response, responselen);
    if(rez != 0)
        return rez;

    strncpy(response+sizeof(int), info->data.filename.c_str(), info->data.filename.length());
    rez = send_msg_socket(sd, response, responselen, 1);
    free(response);
    if(rez != 0)
        return rez;

    rez = prepare_edit_msg_srv_client(edit_data, info->data.size, response, responselen);
    if(rez != 0)
        return rez;

    int offset = sizeof(int);
    rez = convert_to_str(info->data.lines, response+offset);

    rez = send_msg_socket(sd, response, responselen, 1);
    free(response);
    if(rez != 0)
        return rez;

    rez = prepare_edit_msg_srv_client(edit_cursors, 0, response, responselen);
    if(rez != 0)
        return rez;

    file_cursor network_cursors[2];
    network_cursors[0] = htonl(info->cursors[0]);
    network_cursors[1] = htonl(info->cursors[1]);

    memcpy(response + sizeof(int), &network_cursors[0], sizeof(file_cursor));
    memcpy(response + sizeof(int) + sizeof(file_cursor), &network_cursors[1], sizeof(file_cursor));

    rez = send_msg_socket(sd, response, responselen, 1);
    free(response);
    if(rez != 0)
        return rez;
    
    int client_id = 0;
    if(info->connected[0])
    {
        client_id = 1;
    }

    info->connected[client_id] = 1;
    info->client[client_id] = sd;

    info->cursors[client_id].active = 1;
    info->cursors[client_id].line = 0;
    info->cursors[client_id].offset = 0;

    rez = prepare_edit_msg_srv_client(edit_conn, 0, response, responselen);
    if(rez != 0)
        return rez;
    
    ((int*)(response))[1] = htonl(client_id);
    file_cursor network_client_cursor = htonl(info->cursors[client_id]);
    memcpy(response+2*sizeof(int), &network_client_cursor, sizeof(file_cursor));

    int succ[2];
    send_to_clients(data, response, responselen, succ);
    free(response);
    if(succ[client_id] != 0)
        return succ[client_id];

    return 0;
}

void disconnect_client(thread_info &data)
{
    int client_id, sd = data.client_sd, rez;
    if(data.edited_file->client[0] == sd)
        client_id = 0;
    else 
        client_id = 1;

    if(sd == -1)
        data.edited_file->client[client_id] = -1;

    int outmsg[2];
    outmsg[0] = htonl((int)edit_disconn);
    outmsg[1] = htonl(client_id);

    int succ[2];
    send_to_clients(data, (char*)outmsg, 2*sizeof(int), succ);
    
    if(client_id == 0 && data.edited_file->connected[1])
    {
        data.edited_file->connected[1] = 0;
        data.edited_file->cursors[0] = data.edited_file->cursors[1];
        data.edited_file->cursors[1].active = 0;
        data.edited_file->client[0] = data.edited_file->client[1];
    }
    else 
    {
        data.edited_file->connected[client_id] = 0;
        data.edited_file->cursors[client_id].active = 0;

        if(client_id == 0)
        {
            pthread_mutex_lock(&db_mutex);
            
            rez = save_file_in_db(data);
            if(rez != 0)
                printf("[Server thread] Eroare la salvare fisier %d in baza de date (cod %d, dberr %d)\n", data.edited_file->fileid, rez, sqlite3_errcode(database));

            pthread_mutex_unlock(&db_mutex);

            data.edited_file->data.lines.clear();
            data.edited_file->initialized = 0;
        }
    }
}

//edit msg client->srv: act+data
//act = 0 (exit edit)
//act = 6 (disconn)
//act = 7 (char) data=(char)
//act = 8 (arrowkey) data=(char)
//act = 9 (backspace)
//act = 10 (tab)
int perform_edit(thread_info &data, edit_act_srv_client act, int client_id, char* msg, int msglen)
{
    int rez;
    char* outmsg = NULL;
    int outmsglen = 0;
    file_data& filedata = data.edited_file->data;
    file_info* fileinfo = data.edited_file;
    file_cursor& current_cursor = fileinfo->cursors[client_id];
    int other_client_id = 1 - client_id;
    file_cursor& other_cursor = fileinfo->cursors[other_client_id];
    switch(act)
    {
        case edit_char:
        {
            rez = prepare_edit_msg_srv_client(edit_char, 0, outmsg, outmsglen);
            if(rez != 0) break;

            int* outintmsg = (int*)outmsg;
            outintmsg[1] = htonl(client_id);
            char added_char = (outmsg[2*sizeof(int)] = msg[2*sizeof(int)]);

            int succ[2];
            send_to_clients(data, outmsg, outmsglen, succ);
            rez = succ[client_id];

            perform_action_on_file(filedata, current_cursor, other_cursor, act, added_char);

            free(outmsg);
            break;
        }
        case edit_arrow:
        {
            rez = prepare_edit_msg_srv_client(edit_arrow, 0, outmsg, outmsglen);
            if(rez != 0) break;

            int* outintmsg = (int*)outmsg;
            outintmsg[1] = htonl(client_id);
            char arrow = (outmsg[2*sizeof(int)] = msg[2*sizeof(int)]);

            int succ[2];
            send_to_clients(data, outmsg, outmsglen, succ);
            rez = succ[client_id];

            int edit_rez = perform_action_on_file(filedata, current_cursor, other_cursor, act, arrow);
            if(edit_rez == 1)
            {
                printf("[Server thread] Primit sageata incorecta de la client %d pe fisier %d.\n", data.client_sd, fileinfo->fileid);
            }

            free(outmsg);
            break;
        }
        case edit_backspace:
        {
            rez = prepare_edit_msg_srv_client(edit_backspace, 0, outmsg, outmsglen);
            if(rez != 0) break;

            int* outintmsg = (int*)outmsg;
            outintmsg[1] = htonl(client_id);

            int succ[2];
            send_to_clients(data, outmsg, outmsglen, succ);
            rez = succ[client_id];

            perform_action_on_file(filedata, current_cursor, other_cursor, act, 0);

            free(outmsg);
            break;
        }
        case edit_tab:
        {
            rez = prepare_edit_msg_srv_client(edit_tab, 0, outmsg, outmsglen);
            if(rez != 0) break;

            int* outintmsg = (int*)outmsg;
            outintmsg[1] = htonl(client_id);

            int succ[2];
            send_to_clients(data, outmsg, outmsglen, succ);
            rez = succ[client_id];

            perform_action_on_file(filedata, current_cursor, other_cursor, act, 0);

            free(outmsg);
            break;
        }
        default: break;
    }

    return rez;
}

int handle_edit(thread_info &data, char* msg, int msglen, std::string &out)
{
    int rez;
    char *saveptr;
    char* cmd, *filename, *test;
    cmd = strtok_r(msg, " ", &saveptr);
    filename = strtok_r(NULL, " ", &saveptr);
    test = strtok_r(NULL, " ", &saveptr);
    if(filename == NULL || test != NULL)
    {
        out = "Eroare: utilizare incorecta. Format: edit <filename>";
        return 0;
    }

    if(!data.logged_in)
    {
        out = "Nu esti logat.";
        return 0;
    }


    pthread_mutex_lock(&file_modif_mutex);
    pthread_mutex_lock(&db_mutex);

    rez = query_get_file(filename);
    if(rez == SQLITE_DONE)
    {
        pthread_mutex_unlock(&db_mutex);
        pthread_mutex_unlock(&file_modif_mutex);
        out = "Nu exista fisier cu numele dat.";
        return 0;
    }

    if(rez != SQLITE_ROW)
    {
        errno = sqlite3_errcode(database);
        pthread_mutex_unlock(&db_mutex);
        pthread_mutex_unlock(&file_modif_mutex);
        return 21;
    }

    int fileid = sqlite3_column_int(get_file, 0);
    int author = sqlite3_column_int(get_file, 3);
    int is_public = sqlite3_column_int(get_file, 4);

    if(!is_public && author != data.logged_user_id)
    {
        rez = query_get_allowed(data.logged_user_id, fileid);
        if(rez == SQLITE_DONE)
        {
            pthread_mutex_unlock(&db_mutex);
            pthread_mutex_unlock(&file_modif_mutex);
            out = "Nu ai permisiune de a edita fisierul cerut.";
            return 0;
        }
        if(rez != SQLITE_ROW)
        {
            errno = sqlite3_errcode(database);
            pthread_mutex_unlock(&db_mutex);
            pthread_mutex_unlock(&file_modif_mutex);
            return 21;
        }
    }
    pthread_mutex_unlock(&db_mutex);

    pthread_mutex_lock(&map_mutex);

    if(open_files.count(filename) == 1 && open_files[filename] != nullptr)
    {
        data.edited_file = open_files[filename];
    }
    else
    {
        data.edited_file = (file_info*)(malloc(sizeof(file_info)));
        if(data.edited_file == NULL)
        {
            pthread_mutex_unlock(&map_mutex);
            pthread_mutex_unlock(&file_modif_mutex);
            return 11;
        }
        new(data.edited_file) file_info();
        open_files[filename] = data.edited_file;

        data.edited_file->data.filename = filename;
        data.edited_file->data.size = 0;

        data.edited_file->cursors[0].active = 0;
        data.edited_file->cursors[1].active = 0;
        data.edited_file->connected[0] = 0;
        data.edited_file->connected[0] = 0;

        data.edited_file->fileid = fileid;
    
        data.edited_file->data.lines.clear();
        data.edited_file->data.lines.push_back("");
    }

    pthread_mutex_lock(&data.edited_file->access_mutex);

    if(data.edited_file->connected[0] && data.edited_file->connected[1])
    {
        pthread_mutex_unlock(&data.edited_file->access_mutex);
        pthread_mutex_unlock(&map_mutex);
        pthread_mutex_unlock(&file_modif_mutex);
        out = "Exista deja doi clienti care editeaza fisierul cerut.";
        return 0;
    }

    rez = connect_client(data, filename);

    pthread_mutex_unlock(&data.edited_file->access_mutex);
    pthread_mutex_unlock(&map_mutex);
    pthread_mutex_unlock(&file_modif_mutex);

    if(rez != 0)
        return rez;

    data.edit_mode = 1;

    out = "opened";
    return 0;
}

void* handle_client(void* tiptr)
{
    signal(SIGPIPE, SIG_IGN);
    thread_info &data = *(thread_info*)tiptr;

    data.thread_id = pthread_self();

    int sd = data.client_sd;
    int rez;
    while(1)
    {
        if(data.edit_mode)
        {
            char* recv_msg = NULL;
            int recv_msglen = 0;

            rez = receive_msg_socket(sd, recv_msg, recv_msglen);

            pthread_mutex_lock(&data.edited_file->access_mutex);
            if(rez != 0)
            {
                if(rez == 10)
                    data.client_sd = -1;
                disconnect_client(data);
                pthread_mutex_unlock(&data.edited_file->access_mutex);

                if(rez == 10 || (rez==9 && errno == EPIPE))
                {
                    printf("[Server thread] Clientul a inchis conexiunea.\n");
                    free(recv_msg);
                    break;
                }
                else
                {
                    free(recv_msg);
                    close(sd);
                    (&data)->~thread_info();
                    free(tiptr);
                    handle_error(rez, 1);
                }
            }

            int client_id;
            if(data.edited_file->client[0] == sd)
                client_id = 0;
            else 
                client_id = 1;

            int* recv_intmsg = (int*)recv_msg;
            if(ntohl(recv_intmsg[0]) != 1) //wrong type?
            {
                pthread_mutex_unlock(&data.edited_file->access_mutex);
                free(recv_msg);
                continue;
            }

            edit_act_srv_client act = (edit_act_srv_client)ntohl(recv_intmsg[1]);
            if(act == edit_disconn)
            {
                disconnect_client(data);
                pthread_mutex_unlock(&data.edited_file->access_mutex);
                free(recv_msg);
                break;
            }
            if(act == edit_deny)
            {
                disconnect_client(data);
                pthread_mutex_unlock(&data.edited_file->access_mutex);
                free(recv_msg);
                data.edited_file = NULL;
                data.edit_mode = 0;
                continue;
            }

            rez = perform_edit(data, act, client_id, recv_msg, recv_msglen);

            free(recv_msg);
            
            if(rez != 0)
            {
                disconnect_client(data);
                pthread_mutex_unlock(&data.edited_file->access_mutex);
                close(sd);
                (&data)->~thread_info();
                free(tiptr);
                handle_error(rez, 1);
            }

            pthread_mutex_unlock(&data.edited_file->access_mutex);
        }
        else
        {
            char* recv_msg = NULL;
            int recv_msglen = 0;
        
            rez = receive_msg_socket(sd, recv_msg, recv_msglen);
            if(rez == 10 || (rez==9 && errno == EPIPE))
            {
                printf("[Server thread] Clientul a inchis conexiunea.\n");
                break;
            }

            if(rez != 0)
            {
                close(sd);
                (&data)->~thread_info();
                free(tiptr);
                handle_error(rez, 1);
            }

            int type = ntohl(*(int*)recv_msg);
            if(type != 0)
            {
                free(recv_msg); continue; //wrong type?
            }
            char* client_msg = recv_msg + sizeof(int);
            int client_msglen = recv_msglen - sizeof(int);
            std::string response_str;

            if(strncmp(client_msg, "login", 5) == 0)
            {
                rez = handle_login(data, client_msg, client_msglen, response_str);
            }
            else if(strncmp(client_msg, "register", 6) == 0)
            {
                rez = handle_register(data, client_msg, client_msglen, response_str);
            }
            else if(strncmp(client_msg, "logout", 6) == 0)
            {
                rez = handle_logout(data, client_msg, client_msglen, response_str);
            }
            else if(strncmp(client_msg, "create_file", 11) == 0)
            {
                rez = handle_create_file(data, client_msg, client_msglen, response_str);
            }
            else if(strncmp(client_msg, "rename_file", 11) == 0)
            {
                rez = handle_rename_file(data, client_msg, client_msglen, response_str);
            }
            else if(strncmp(client_msg, "delete_file", 11) == 0)
            {
                rez = handle_delete_file(data, client_msg, client_msglen, response_str);
            }
            else if(strncmp(client_msg, "allow", 5) == 0)
            {
                rez = handle_allow(data, client_msg, client_msglen, response_str);
            }
            else if(strncmp(client_msg, "disallow", 8) == 0)
            {
                rez = handle_disallow(data, client_msg, client_msglen, response_str);
            }
            else if(strncmp(client_msg, "make_public", 11) == 0)
            {
                rez = handle_public(data, client_msg, client_msglen, response_str);
            }
            else if(strncmp(client_msg, "make_private", 12) == 0)
            {
                rez = handle_private(data, client_msg, client_msglen, response_str);
            }
            else if(strncmp(client_msg, "download", 8) == 0)
            {
                rez = handle_download(data, client_msg, client_msglen, response_str);
            }
            else if(strncmp(client_msg, "list", 4) == 0)
            {
                rez = handle_list(data, client_msg, client_msglen, response_str);
            }
            else if(strncmp(client_msg, "edit", 4) == 0)
            {
                rez = handle_edit(data, client_msg, client_msglen, response_str);
            }
            else
            {
                response_str = "Comanda invalida.";
            }

            free(recv_msg);

            if(rez != 0)
            {
                close(sd);
                (&data)->~thread_info();
                free(tiptr);
                handle_error(rez, 1);
            }

            if(data.edit_mode || response_str == "") continue;

            char* response = (char*)response_str.c_str();
            int responselen = response_str.length();

            rez = send_msg_socket(sd, response, responselen);
            if(rez != 0)
            {
                close(sd);
                (&data)->~thread_info();
                free(tiptr);
                handle_error(rez, 1);
            }
        }
    }
    close(sd);
    (&data)->~thread_info();
    free(tiptr);
    return NULL;
}

int main(int argc, char* argv[])
{
    sockaddr_in server;
    sockaddr_in from;

    int rez;

    if(argc >= 2)
        init_sql(argv[1]);
    else
        init_sql("collabnotepad.db");

    int sd = socket(AF_INET, SOCK_STREAM, 0);

    if (sd == -1)
        handle_error(2);

    int enable = 1;
    rez = setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &enable, (socklen_t)sizeof(enable));
    if(rez == -1)
        handle_error(3);
    rez = setsockopt(sd, SOL_SOCKET, SO_KEEPALIVE, &enable, (socklen_t)sizeof(enable));
    if(rez == -1)
        handle_error(3);
    rez = setsockopt(sd, IPPROTO_TCP, TCP_NODELAY, &enable, (socklen_t)sizeof(enable));
    if(rez == -1)
        handle_error(3);

    server.sin_family = AF_INET;
    server.sin_addr.s_addr = htonl(INADDR_ANY);
    server.sin_port = htons(PORT);

    rez = bind(sd, (sockaddr *)&server, sizeof(sockaddr));
    if (rez == -1)
        handle_error(4);

    rez = listen(sd, 10);
    if (rez == -1)
        handle_error(5);

    while (1)
    {
        printf("[Server] Astept conexiuni.\n");
        int length = sizeof(from);
        int client = accept(sd, (sockaddr *)&from, (socklen_t *)(&length)); 
        if (client == -1)
        {
            printf("[Server] Nu am putut accepta conexiunea de la client"); perror(0);
            continue;
        }
        
        enable = 90000;
        rez = setsockopt(sd, IPPROTO_TCP, TCP_USER_TIMEOUT, &enable, (socklen_t)sizeof(enable));
        if(rez == -1)
        {
           printf("[Server] Eroare la setare optiune pe socket: "); fflush(NULL); perror(0);
           close(client);
           continue;
        }

        thread_info* tiptr = (thread_info*)(malloc(sizeof(thread_info)));
        new(tiptr) thread_info();
        tiptr->client_sd = client;
        printf("[Server] Am stabilit conexiune, pornesc thread.\n");
        errno = pthread_create(&tiptr->thread_id, NULL, &handle_client, tiptr);
        if(errno != 0)
        {
            printf("[Server] Eroare la creare thread"); fflush(NULL); perror(0);
            close(client);
            tiptr->~thread_info();
            free(tiptr);
            continue;
        }

        errno = pthread_detach(tiptr->thread_id);
        if(errno != 0)
        {
            printf("[Server] Eroare la detach"); fflush(NULL); perror(0);
            continue;
        }
    }
};
