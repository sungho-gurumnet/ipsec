#include <stdio.h>
#include <pthread.h>

void func()
{
	int i;

	while(1)
	{
		if (i==10) break;
		printf("ID: %d \n", pthread_self());
		sleep(1);
		i++;
	}
	// pthread_join(pthread_self(), NULL);
}

int main(void)
{
	int i;
	// pthread_t hThread;

	for (i=0; i<2; i++)
	{
		// pthread_create(&hThread, NULL, (void *)func, NULL);
		func();
	}
}
