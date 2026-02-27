#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <string.h>
#include <arpa/inet.h>
#include <signal.h>
#include <netinet/tcp.h>
#include <fcntl.h>

#include <fstream>

#include <ncurses.h>

#include "common.h"

std::ofstream debug;

char *cmdbuf;
int bufsize, buflen;

int edit_mode = 0;
int just_connected = 0;
int client_id = 0;

int curses_init = 0;
int curses_active = 0;

file_data data;
file_cursor cursors[2];

unsigned int top_line_index = 0, left_col_index = 0;
int has_resized = 0;

void handle_error(int cod)
{
    if(curses_active) endwin();
    switch(cod)
    {
        case 1: printf("[Client] Eroare la realloc(): "); fflush(NULL); perror(0); break;
        case 2: printf("[Client] Utilizare incorecta. Format: ./client <ip> <port>\n"); break;
        case 3: printf("[Client] Eroare la deschidere socket: "); fflush(NULL); perror(0); break;
        case 4: printf("[Client] IP invalid.\n"); break;
        case 5: printf("[Client] Eroare la setare optiune pe socket: "); fflush(NULL); perror(0); break;
        case 6: printf("[Client] Eroare la conexiune: "); fflush(NULL); perror(0); break;
        case 7: printf("[Client] Eroare la write() spre server: "); fflush(NULL); perror(0); break;
        case 9: printf("[Client] Eroare la read() de la server: "); fflush(NULL); perror(0); break;
        case 11: printf("[Client] Eroare la malloc(): "); fflush(NULL); perror(0); break;
        case 13: printf("[Client] Eroare la select(): "); fflush(NULL); perror(0); break;
        default: printf("[Client] Eroare cod %d: ", cod); fflush(NULL); perror(0); break;
    }
    exit(cod);
}

void increase_buf()
{
    bufsize += 1024;
    cmdbuf = (char*)realloc(cmdbuf, bufsize);
    if(cmdbuf == NULL)
        handle_error(1);
}

void read_stdin()
{   
    buflen = 0;
    while(1)
    {
        char ch;
        int rez = read(STDIN_FILENO, &ch, 1);
        if(rez == -1 && errno == EINTR) continue;
        if(rez == -1)
            handle_error(6);
        if(rez == 0)
        {
            printf("\n[Client] Am citit EOF, stop!\n");
            exit(0);
        }
        if(buflen + 2 >= bufsize)
        {
            increase_buf();
        }
        if(ch == '\n') break;
        cmdbuf[buflen] = ch;
        buflen++;
    }
    cmdbuf[buflen] = 0;
}

int send_msg_socket(int sd, char* msg, int len, int type = 0)
{
    int sent = 0, target = sizeof(int);
    int rez;
    len += sizeof(int);
    int network_len = htonl(len);
    char* lenptr = (char*)(&network_len);
    while(sent < target)
    {
        rez = write(sd, lenptr+sent, target - sent);
        if(rez == -1)
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
    sent = 0; target = len;
    while(sent < target)
    {
        rez = write(sd, msg+sent, target - sent);
        if(rez == -1)
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

int perform_edit(char* msg, int msglen)
{
    int* intmsg = (int*)msg;
    edit_act_srv_client act = (edit_act_srv_client)ntohl(intmsg[1]);
    int rez = 0;

    switch(act)
    {
        case edit_deny:
        case edit_accept:
        {
            break;
        }
        case edit_filename:
        {
            char* filename = msg+2*sizeof(int);
            data.filename = filename;
            break;
        }
        case edit_data:
        {
            char* contents = msg + 2*sizeof(int);
            data.size = msglen - 2*sizeof(int);
            load_file(data, contents);
            break;
        }
        case edit_cursors:
        {
            file_cursor *cursors_ptr = (file_cursor*)(msg+2*sizeof(int));
            cursors[0] = ntohl(cursors_ptr[0]);
            cursors[1] = ntohl(cursors_ptr[1]);
            break;
        }
        case edit_conn:
        {
            int conn_id = ntohl(intmsg[2]);
            file_cursor *cursor_ptr = (file_cursor*)(msg+3*sizeof(int));
            cursors[conn_id] = ntohl(*cursor_ptr);

            if(just_connected)
            {
                client_id = conn_id;
            }

            break;
        }
        case edit_disconn:
        {
            int conn_id = ntohl(intmsg[2]);
            cursors[conn_id].active = 0;

            if(conn_id == client_id)
            {
                data.lines.clear();
                data.filename.clear();
                edit_mode = 0;
                cursors[0].active = cursors[1].active = 0;
                endwin(); curses_active = 0;
                printf("Am iesit din modul editare.\n\n");
                break;
            }
            if(conn_id == 0 && cursors[1].active)
            {
                cursors[0] = cursors[1];
                cursors[1].active = 0;
                client_id = 0;
            }
            
            break;
        }
        case edit_char:
        {
            int conn_id = ntohl(intmsg[2]);
            char inserted = msg[3*sizeof(int)];

            perform_action_on_file(data, cursors[conn_id], cursors[1-conn_id], act, inserted);
            break;
        }
        case edit_arrow:
        {
            int conn_id = ntohl(intmsg[2]);
            char arrow = msg[3*sizeof(int)];

            perform_action_on_file(data, cursors[conn_id], cursors[1-conn_id], act, arrow);
            break;
        }
        case edit_backspace:
        case edit_tab:
        {
            int conn_id = ntohl(intmsg[2]);

            perform_action_on_file(data, cursors[conn_id], cursors[1-conn_id], act, 0);
            break;
        }
        default: break;
    }

    return rez;
}

int send_action_server(int sd)
{
    int rez = 0;
    int ch = getch();

    if(ch == 3)  //ctrl+c
        kill(getpid(), SIGINT);

    if(ch == 27) //esc
    {
        edit_act_srv_client act = edit_deny;
        int network_act = htonl((int)act);

        rez = send_msg_socket(sd, (char*)&network_act, sizeof(int), 1);
        if(rez != 0)
            return rez;

        return 0;
    }
    
    if(ch == KEY_BACKSPACE || ch == 127 || ch == '\b')
    {
        edit_act_srv_client act = edit_backspace;
        int network_act = htonl((int)act);
        
        rez = send_msg_socket(sd, (char*)&network_act, sizeof(int), 1);
        if(rez != 0)
            return rez;

        return 0;
    }

    if(ch == KEY_STAB || ch == '\t')
    {
        edit_act_srv_client act = edit_tab;
        int network_act = htonl((int)act);
        
        rez = send_msg_socket(sd, (char*)&network_act, sizeof(int), 1);
        if(rez != 0)
            return rez;

        return 0;
    }

    if(ch == KEY_DOWN || ch == KEY_UP || ch == KEY_LEFT || ch == KEY_RIGHT)
    {
        char arrow;
        switch(ch)
        {
            case KEY_DOWN: arrow = 0; break;
            case KEY_UP: arrow = 1; break;
            case KEY_LEFT: arrow = 2; break;
            case KEY_RIGHT: arrow = 3; break;
            default: arrow = 4; break;
        }

        char msg[sizeof(int)+1];
        *(int*)msg = htonl((int)edit_arrow);
        msg[sizeof(int)] = arrow;

        rez = send_msg_socket(sd, msg, sizeof(int)+1, 1);
    }

    if(check_accepted(ch))
    {
        char msg[sizeof(int)+1];
        *(int*)msg = htonl((int)edit_char);
        msg[sizeof(int)] = ch;

        rez = send_msg_socket(sd, msg, sizeof(int)+1, 1);
    }
    
    return rez;
}

int get_action_server(int sd)
{
    int rez;

    char* recv_msg = NULL;
    int recv_msglen = 0;

    rez = receive_msg_socket(sd, recv_msg, recv_msglen);
    if(rez != 0)
        return rez;

    int* recv_intmsg = (int*)recv_msg;
    if(ntohl(recv_intmsg[0]) != 1)
    {
        free(recv_msg);
        return 0;
    }

    rez = perform_edit(recv_msg, recv_msglen);
    if(rez != 0)
        return rez;

    free(recv_msg);

    return 0;
}

void handle_resize(int sig)
{
    has_resized = 1;
}

void init_ncurses()
{
    curses_active = 1;

    noecho();
    raw();
    keypad(stdscr, 1);
    clear();
}

void print_file()
{
    unsigned int i;
    unsigned int lines, cols;
    getmaxyx(stdscr, lines, cols);

    unsigned int start_line = 2;
    unsigned int finish_line = lines-2;

    unsigned int edit_area_lines = lines - 4;

    if(top_line_index > cursors[client_id].line)
        top_line_index = cursors[client_id].line;
    if(top_line_index + edit_area_lines <= cursors[client_id].line)
        top_line_index = cursors[client_id].line - edit_area_lines + 1;
    if(left_col_index > cursors[client_id].offset)
        left_col_index = cursors[client_id].offset;
    if(left_col_index + cols <= cursors[client_id].offset)
        left_col_index = cursors[client_id].offset - cols + 1;

    move(0,0);
    attron(A_REVERSE);
    printw("%.*s", cols, data.filename.c_str());
    for(i = data.filename.length(); i < cols; i++)
        addch(' ');

    char conectati_str[] = "Conectati: 1";
    if(cursors[1].active)
        conectati_str[strlen(conectati_str)-1] = '2';

    move(0, cols - strlen(conectati_str) - 1);
    printw("%s", conectati_str);
    attroff(A_REVERSE);

    move(start_line-1, 0);
    clrtoeol();

    for(i = start_line; top_line_index + i - start_line < data.lines.size() && i < finish_line; i++)
    {
        move(i, 0);
        unsigned int lineindex = top_line_index + i - start_line;
        if(data.lines[lineindex].length() > left_col_index)
            printw("%.*s", cols, data.lines[lineindex].c_str()+left_col_index);
        
        clrtoeol();
    }
    
    for(; i < finish_line; i++)
    {
        move(i, 0);
        clrtoeol();
    }

    move(finish_line, 0);
    clrtoeol();

    move(lines-1, 0);
    attron(A_REVERSE);
    char exit_str[] = "Apasa ESC pentru a iesi din modul editare.";
    printw("%s", exit_str);
    for(i = strlen(exit_str); i < cols; i++)
        addch(' ');
    attroff(A_REVERSE);
    
    unsigned int other_client_id = 1 - client_id;
    if(cursors[other_client_id].active)
    {
        unsigned int other_line = cursors[other_client_id].line, other_offset = cursors[other_client_id].offset;
        if(other_line >= top_line_index && other_line < top_line_index + edit_area_lines && other_offset >= left_col_index && other_offset < left_col_index + cols)
        {
            move(cursors[other_client_id].line - top_line_index + start_line, cursors[other_client_id].offset - left_col_index);
            chgat(1, 0, 3, NULL);
        }
    }

    move(cursors[client_id].line - top_line_index + start_line, cursors[client_id].offset - left_col_index);
    refresh();
}

void initial_connect(int sd)
{
    int rez;
            
    char* recv_msg = NULL;
    int recv_msglen = 0;

    //filename
    rez = receive_msg_socket(sd, recv_msg, recv_msglen);
    if(rez != 0)
        handle_error(rez);
    
    rez = perform_edit(recv_msg, recv_msglen);
    if(rez != 0)
        handle_error(rez);
    
    free(recv_msg);

    //file contents
    rez = receive_msg_socket(sd, recv_msg, recv_msglen);
    if(rez != 0)
        handle_error(rez);
    
    rez = perform_edit(recv_msg, recv_msglen);
    if(rez != 0)
        handle_error(rez);
    
    free(recv_msg);

    //cursors
    rez = receive_msg_socket(sd, recv_msg, recv_msglen);
    if(rez != 0)
        handle_error(rez);

    rez = perform_edit(recv_msg, recv_msglen);
    if(rez != 0)
        handle_error(rez);
    
    free(recv_msg);

    //client connected
    rez = receive_msg_socket(sd, recv_msg, recv_msglen);
    if(rez != 0)
        handle_error(rez);

    rez = perform_edit(recv_msg, recv_msglen);
    if(rez != 0)
        handle_error(rez);
    
    free(recv_msg);

    if(curses_init == 0)
    {
        initscr(); start_color(); use_default_colors(); init_pair(3, COLOR_WHITE, COLOR_BLUE);
        set_escdelay(100);

        signal(SIGWINCH, handle_resize);
        curses_init = 1;
    }

    init_ncurses();

    print_file();
    refresh();
}

void receive_file(int sd)
{
    int rez;

    char *recv_filename = NULL, *recv_contents = NULL;
    int recv_filenamelen = 0, recv_contentslen = 0;

    //filename
    rez = receive_msg_socket(sd, recv_filename, recv_filenamelen);
    if(rez != 0)
        handle_error(rez);

    //file contents
    rez = receive_msg_socket(sd, recv_contents, recv_contentslen);
    if(rez != 0)
        handle_error(rez);

    const char* filename = recv_filename + 2*sizeof(int);
    const char* contents = recv_contents + 2*sizeof(int);

    int downloadedfd = open(filename, O_EXCL | O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if(downloadedfd == -1)
    {
        printf("Nu am putut salva fisierul caci exista deja unul cu numele primit (%s).\n\n", filename);

        free(recv_filename);
        free(recv_contents);
        return;
    }

    int contentslen = recv_contentslen - 2*sizeof(int);
    rez = write(downloadedfd, contents, contentslen);
    if(rez != contentslen)
    {
        printf("Nu am putut salva intreg fisierul, eroare: "); fflush(NULL); perror(0);
        printf("\n");

        free(recv_filename);
        free(recv_contents);
        return;
    }

    printf("Fisier descarcat.\n\n");
    free(recv_filename);
    free(recv_contents);
    close(downloadedfd);
}

int main(int argc, char *argv[])
{
    if(argc != 3)
        handle_error(2);

    int rez;
    int sd = socket(AF_INET, SOCK_STREAM, 0);
    if (sd == -1)
        handle_error(3);

    sockaddr_in server; 
    server.sin_family = AF_INET;
    
    rez = inet_aton(argv[1], &server.sin_addr);
    if(rez == 0)
        handle_error(4);
    server.sin_addr.s_addr = inet_addr(argv[1]);

    unsigned short port = atoi(argv[2]);
    server.sin_port = htons(port);

    int enable = 1;
    rez = setsockopt(sd, SOL_SOCKET, SO_KEEPALIVE, &enable, (socklen_t)sizeof(enable));
    if(rez == -1)
        handle_error(5);
    rez = setsockopt(sd, IPPROTO_TCP, TCP_NODELAY, &enable, (socklen_t)sizeof(enable));
    if(rez == -1)
        handle_error(5);
    enable = 60;
    rez = setsockopt(sd, IPPROTO_TCP, TCP_KEEPIDLE, &enable, (socklen_t)sizeof(enable));
    if(rez == -1)
        handle_error(5);

    rez = connect(sd, (sockaddr *)&server, sizeof(sockaddr));

    if (rez == -1)
        handle_error(6);

    signal(SIGPIPE, SIG_IGN);
    
    printf("[Client] Conectat la server.\n");

    fd_set readfds;
    
    increase_buf();

    while(1)
    {
        if(edit_mode)
        {
            if(just_connected)
            {
                printf("Cerere editare acceptata, deschid fisierul...\n");
                initial_connect(sd);
                just_connected = 0;
                continue;
            }

            if(has_resized)
            {
                has_resized = 0;
                endwin(); 
                init_ncurses();
                refresh();
                print_file();
            }

            FD_ZERO(&readfds);
            FD_SET(STDIN_FILENO, &readfds);
            FD_SET(sd, &readfds);

            rez = select(sd+1, &readfds, NULL, NULL, NULL);
            if(rez < 0 && errno == EINTR) continue;
            if(rez < 0)
            {
                endwin(); curses_active = 0;
                handle_error(13);
            }

            if(FD_ISSET(STDIN_FILENO, &readfds))
            {
                rez = send_action_server(sd);
                if(rez == 7)
                {
                    endwin();
                    printf("[Client] Serverul a inchis conexiunea.\n");
                    return 0;
                }
                if(rez != 0)
                    handle_error(rez);
            }
            
            if(FD_ISSET(sd, &readfds))
            {
                rez = get_action_server(sd);
                if(rez == 10)
                {
                    endwin();
                    printf("[Client] Serverul a inchis conexiunea.\n");
                    return 0;
                }
                if(rez != 0)
                    handle_error(rez);

                if(edit_mode)
                    print_file();
            }
        }
        else
        {
            printf("[Client] Comanda: "); fflush(NULL);
            read_stdin();
            printf("after read\n");
            if(strncmp(cmdbuf, "exit", 4) == 0)
            {
                printf("[Client] Inchid.\n");
                exit(0);
            }

            rez = send_msg_socket(sd, cmdbuf, buflen);
            if(rez == 7)
            {
                printf("[Client] Serverul a inchis conexiunea.\n");
                return 0;
            }
            printf("after send\n");
            if(rez != 0)
                handle_error(rez);

            char* recv_msg = NULL;
            int recv_msglen = 0;

            rez = receive_msg_socket(sd, recv_msg, recv_msglen);

            if(rez == 10)
            {
                printf("[Client] Serverul a inchis conexiunea.\n");
                return 0;
            }
            if(rez != 0)
                handle_error(rez);

            int type = ntohl(*(int*)recv_msg);
            if(type != 0)
            {
                char* cmd = strtok(cmdbuf, " ");
                if(strncmp(cmd, "edit", 4) == 0)
                {
                    edit_mode = 1; just_connected = 1;
                }
                else if(strncmp(cmd, "download", 8) == 0)
                {
                    receive_file(sd);
                }
                free(recv_msg); continue;
            }

            char* text = recv_msg+sizeof(int);
            printf("%s\n\n", text);
            free(recv_msg);
        }
    }

    return 0;
}
