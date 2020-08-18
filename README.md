# sh-reqid

Having have to work with buggy application that send twice (or more) the same HTTP request which could be troublesome in some case, I set up a small history using PHP session, but PHP session use file locking which can be slow. You can setup a Redis server (or anything alike) to handle PHP session but this might be a bit heavy in some use case. So the idea is to use shared memory and semaphore ... it might be faster and lighter to setup (in fact, no setup at all).

This is a work in progress.