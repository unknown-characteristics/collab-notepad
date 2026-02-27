# collab-notepad
Collaborative Notepad project for the Computer Networks course, which allows two people to simultaneously edit a text file in the terminal in real-time.

The project is designed for Linux systems.
The client uses the ncurses library for the terminal interaction.
The server uses an SQLite3 database for user credentials, existing files and access privileges, while storing the data from the files directly on the filesystem.

The application supports creating and editing text files in parallel, with each file being edited by at most two users at once. Users can see the other person's cursor position and their changes in real time. The server processsing code for the client's changes is carefully implemented using mutexes to properly handle simultaneous editing of the same region in a file. A file may be either public, for all users to access and edit, or private, in which case the file's creator can specify usernames to allow other users access to the file.

The project may be improved by adding support for more editing features (copy/paste) or by allowing multiple editors at a time on the same file.
