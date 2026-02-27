#ifndef COLLABNPAD_COMMON_H
#define COLLABNPAD_COMMON_H

#include <string.h>

#include <vector>
#include <string>

#define TAB_SIZE 4

struct file_data
{
    std::vector<std::string> lines;
    std::string filename;
    int size; //total num of chars + 1 newline char for each line except last
};

struct file_cursor
{
    unsigned int active;
    unsigned int line;
    unsigned int offset;
};

//edit msg srv->client: act + data 
//act = 0 (client exit/server deny (unused))
//act = 1 (server accept)
//act = 2 (file send filename) (filename)
//act = 3 (file send data) (contents)
//act = 4 (file send cursors) (c1+c2)
//act = 5 (client connected) (client id, cursor)
//act = 6 (client disconnected) (client id)
//act = 7 (client char) (client id, char)
//act = 8 (client arrowkey) (client id, 0/1/2/3)
//act = 9 (client backspace) (client id)
//act = 10 (client tab) (client id)
enum edit_act_srv_client : int
{
    edit_deny = 0,
    edit_accept,
    edit_filename,
    edit_data,
    edit_cursors,
    edit_conn,
    edit_disconn,
    edit_char,
    edit_arrow,
    edit_backspace,
    edit_tab
};

void load_file(file_data &data, const char* filedata);
int convert_to_str(std::vector<std::string> &lines, char* out);
int check_accepted(char ch);
int perform_action_on_file(file_data &filedata, file_cursor &current_cursor, file_cursor &other_cursor, edit_act_srv_client act, char extra);

file_cursor htonl(const file_cursor &cursor);
file_cursor ntohl(const file_cursor &cursor);

#endif