#include <stdio.h>
#include <lock.h>
#include "rwlock.h"

bool cmpxchg(uint8_t volatile* s1, uint8_t s2, uint8_t d);

void rwlock_init(RWLock* rwlock) {
	rwlock->write_lock = 0;
	rwlock->read_lock = 0;

	rwlock->read_count_lock = 0;
	rwlock->read_count = 0;
}

void rwlock_write_lock(RWLock* rwlock) {
	lock_lock(&rwlock->write_lock);
	lock_lock(&rwlock->read_lock);
	
	while(1) {
		lock_lock(&rwlock->read_count_lock);
		if(rwlock->read_count == 0) {
			lock_unlock(&rwlock->read_count_lock);
			return;
		}
		lock_unlock(&rwlock->read_count_lock);

		__asm__ __volatile__  ("nop");
	}
}

bool rwlock_write_try_lock(RWLock* rwlock) {
	if(!lock_trylock(&rwlock->write_lock))
		return false;

	if(!lock_trylock(&rwlock->read_lock)) {
		goto unlock_write_lock;
	}

	if(!lock_trylock(&rwlock->read_count_lock)) {
		goto unlock_read_lock;
	}

	if(rwlock->read_count > 0)
		goto unlock_read_count_lock;

	lock_unlock(&rwlock->read_count_lock);

	return true;

unlock_read_count_lock:
	lock_unlock(&rwlock->read_count_lock);

unlock_read_lock:
	lock_unlock(&rwlock->read_lock);

unlock_write_lock:
	lock_unlock(&rwlock->write_lock);

	return false;
}

void rwlock_write_unlock(RWLock* rwlock) {
	lock_unlock(&rwlock->read_lock);
	lock_unlock(&rwlock->write_lock);
}

void rwlock_read_lock(RWLock* rwlock) {
	lock_lock(&rwlock->read_lock);
	lock_lock(&rwlock->read_count_lock);
	rwlock->read_count++;
	lock_unlock(&rwlock->read_count_lock);
	lock_unlock(&rwlock->read_lock);
}

bool rwlock_read_try_lock(RWLock* rwlock) {
	if(!lock_trylock(&rwlock->read_lock))
		return false;

	if(!lock_trylock(&rwlock->read_count_lock))
		goto unlock_read_lock;

	rwlock->read_count++;

	lock_unlock(&rwlock->read_count_lock);
	lock_unlock(&rwlock->read_lock);

	return true;

unlock_read_lock:
	lock_unlock(&rwlock->read_lock);

	return false;
}

void rwlock_read_unlock(RWLock* rwlock) {
	lock_lock(&rwlock->read_count_lock);
	rwlock->read_count--;
	lock_unlock(&rwlock->read_count_lock);
}
