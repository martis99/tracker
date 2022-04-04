#ifndef QUEUE_H
#define QUEUE_H

#include <pthread.h>

typedef struct QueueNode QueueNode;

typedef struct Queue {
   pthread_mutex_t mutex;
   pthread_cond_t read;
   pthread_cond_t write;
   QueueNode *head;
   QueueNode *tail;
   unsigned int length;
   unsigned int size;
} Queue;

Queue *queue_new(unsigned int size);

void queue_push_head(Queue *queue, void *data);
void *queue_pop_tail(Queue *queue);

#endif