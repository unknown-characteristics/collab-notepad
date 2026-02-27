#include "common.h"
#include <arpa/inet.h>
#include <netinet/in.h>

void load_file(file_data &data, const char* filedata)
{
    data.lines.clear();

    int i, lineindex = 0;

    data.lines.push_back("");
    data.size = 0;
    
    if(filedata == NULL) return;

    for(i = 0; filedata[i] != 0; i++)
    {
        data.size++;
        if(filedata[i] == '\n')
        {
            data.lines.push_back(""); lineindex++;
        }
        else
        {
            data.lines[lineindex].push_back(filedata[i]);
        }
    }
}

int convert_to_str(std::vector<std::string> &lines, char* out)
{
    unsigned int i;

    int offset = 0;
    for(i = 0; i < lines.size(); i++)
    {
        strncpy(out+offset, lines[i].c_str(), lines[i].length());
        offset += lines[i].length();
        
        if(i < lines.size() - 1)
        {
            out[offset++] = '\n';
        }
    }

    return 0;
}

int check_accepted(char ch)
{
    return strchr("\n abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*(),./;'[]\\<>?:\"{}|-=_+`~", ch) != NULL;
}

int perform_action_on_file(file_data &filedata, file_cursor &current_cursor, file_cursor &other_cursor, edit_act_srv_client act, char extra)
{
    switch(act)
    {
        case edit_char:
        {
            char added_char = extra;

            if(!check_accepted(added_char)) break;

            if(added_char != '\n')
            {
                filedata.lines[current_cursor.line].insert(current_cursor.offset, 1, added_char);
                
                if(other_cursor.active && other_cursor.line == current_cursor.line && other_cursor.offset >= current_cursor.offset)
                {
                    other_cursor.offset++;
                }
                
                current_cursor.offset++;
            }
            else
            {
                int newline_index = current_cursor.line + 1;
                filedata.lines.insert(filedata.lines.begin() + newline_index, "");

                filedata.lines[newline_index].insert(0, filedata.lines[current_cursor.line], current_cursor.offset);
                filedata.lines[current_cursor.line].erase(current_cursor.offset);
                if(other_cursor.active)
                {
                    if(other_cursor.line == current_cursor.line && other_cursor.offset >= current_cursor.offset)
                    {
                        other_cursor.line++;
                        other_cursor.offset -= current_cursor.offset;
                    }
                    else if(other_cursor.line > current_cursor.line)
                    {
                        other_cursor.line++;
                    }
                }

                current_cursor.line++;
                current_cursor.offset = 0;
            }
            
            filedata.size++;

            break;
        }
        case edit_arrow:
        {
            char arrow = extra;
            switch(arrow)
            {
                case 0: //down
                {
                    if(current_cursor.line == filedata.lines.size() - 1) break;
                    current_cursor.line++;
                    if(current_cursor.offset > filedata.lines[current_cursor.line].length())
                        current_cursor.offset = filedata.lines[current_cursor.line].length();
                    
                    break;
                }
                case 1: //up
                {
                    if(current_cursor.line == 0) break;
                    current_cursor.line--;
                    if(current_cursor.offset > filedata.lines[current_cursor.line].length())
                        current_cursor.offset = filedata.lines[current_cursor.line].length();
                
                    break;
                }
                case 2: //left
                {
                    if(current_cursor.offset == 0)
                    {
                        if(current_cursor.line > 0)
                        {
                            current_cursor.line--;
                            current_cursor.offset = filedata.lines[current_cursor.line].length();
                        }
                    }
                    else
                    {
                        current_cursor.offset--;
                    }

                    break;
                }
                case 3: //right
                {
                    if(current_cursor.offset == filedata.lines[current_cursor.line].length())
                    {
                        if(current_cursor.line < filedata.lines.size()-1)
                        {
                            current_cursor.line++;
                            current_cursor.offset = 0;
                        }
                    }
                    else
                    {
                        current_cursor.offset++;
                    }

                    break;
                }
                default: return 1;
            }

            break;
        }
        case edit_backspace:
        {
            if(current_cursor.offset > 0)
            {
                filedata.lines[current_cursor.line].erase(current_cursor.offset - 1, 1);

                if(other_cursor.active && other_cursor.line == current_cursor.line && other_cursor.offset >= current_cursor.offset)
                {
                    other_cursor.offset--;
                }
                current_cursor.offset--;

                filedata.size--;
            }
            else if(current_cursor.line > 0)
            {
                int prevlen = filedata.lines[current_cursor.line - 1].length();
                filedata.lines[current_cursor.line-1].append(filedata.lines[current_cursor.line]);

                filedata.lines.erase(filedata.lines.begin() + current_cursor.line);

                if(other_cursor.active)
                {
                    if(other_cursor.line == current_cursor.line)
                    {
                        other_cursor.line--;
                        other_cursor.offset += prevlen;
                    }
                    else if(other_cursor.line > current_cursor.line)
                    {
                        other_cursor.line--;
                    }
                }
                
                current_cursor.line--;
                current_cursor.offset = prevlen;

                filedata.size--;
            }

            break;
        }
        case edit_tab:
        {
            int i = TAB_SIZE;
            while(i--)
            {
                perform_action_on_file(filedata,  current_cursor, other_cursor, edit_char, ' ');
            }
        }
        default: break;
    }

    return 0;
}


file_cursor htonl(const file_cursor &cursor)
{
    return {htonl(cursor.active), htonl(cursor.line), htonl(cursor.offset)};
}
file_cursor ntohl(const file_cursor &cursor)
{
    return {ntohl(cursor.active), ntohl(cursor.line), ntohl(cursor.offset)};
}