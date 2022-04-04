#include "queue.h"

#include <limits.h>
#include <stdlib.h>

struct QueueNode {
   QueueNode *next;
   QueueNode *prev;
   void *data;
};

Queue *queue_new(unsigned int size) {
   Queue *q = calloc(1, sizeof(Queue));
   pthread_mutex_init(&q->mutex, NULL);
   pthread_cond_init(&q->read, NULL);
   pthread_cond_init(&q->write, NULL);

   q->head = NULL;
   q->tail = NULL;
   q->length = 0;
   q->size = size;

   return q;
}

void queue_push_head(Queue *queue, void *data) {
   QueueNode *node;

   node = calloc(1, sizeof *node);
   node->data = data;
   node->prev = NULL;
   node->next = NULL;

   pthread_mutex_lock(&queue->mutex);
   while (queue->length == queue->size) {
      pthread_cond_wait(&queue->write, &queue->mutex);
   }

   node->next = queue->head;
   if (node->next != NULL) {
      node->next->prev = node;
   }
   queue->head = node;
   if (queue->tail == NULL) {
      queue->tail = node;
   }
   queue->length++;

   pthread_cond_signal(&queue->read);
   pthread_mutex_unlock(&queue->mutex);
}

void *queue_pop_tail(Queue *queue) {
   QueueNode *node;
   void *ret = NULL;

   pthread_mutex_lock(&queue->mutex);
   while (queue->head == NULL) {
      pthread_cond_wait(&queue->read, &queue->mutex);
   }

   node = queue->tail;
   queue->tail = node->prev;
   if (queue->tail != NULL) {
      queue->tail->next = NULL;
   }
   if (queue->head == node) {
      queue->head = NULL;
   }
   queue->length--;
   pthread_cond_signal(&queue->write);
   pthread_mutex_unlock(&queue->mutex);

   if (node != NULL) {
      ret = node->data;
      free(node);
   }

   return ret;
}