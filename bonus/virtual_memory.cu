/* /bonus/virtual_memory.cu */

#include "virtual_memory.h"
#include <cuda.h>
#include <cuda_runtime.h>
#include <stdio.h>

__device__ int find_LRU(VirtualMemory *vm);

__device__ void init_invert_page_table(VirtualMemory *vm) {

  for (int i = 0; i < vm->PAGE_ENTRIES; i++) {
    vm->invert_page_table[i] = 0x80000000 + vm->thread_id; // invalid := MSB is 1.
    vm->invert_page_table[i + vm->PAGE_ENTRIES] = i;

    // record the time stamp of each page which would be useful in LRU algorithm
    vm->invert_page_table[i + 2 * vm->PAGE_ENTRIES] = i;  
  }
  vm->invert_page_table[3 * vm->PAGE_ENTRIES] = vm->PAGE_ENTRIES - 1;  // current time stamp
  vm->invert_page_table[3 * vm->PAGE_ENTRIES + 1] = 0;  // LRU entry index
}

__device__ void init_sw_table(VirtualMemory *vm) {

  /* In total 4096(128 kb / 32b = 4096) entries in the table, each connects the secondary addr to the physical addr. */
  for (int i = 0; i < (vm->STORAGE_SIZE / vm->PAGESIZE); i++){
    vm->sw_table[i] = 6000;
  }
}

__device__ void vm_init(VirtualMemory *vm, uchar *buffer, uchar *storage,
                        u32 *invert_page_table, u32 *swap_table, int *pagefault_num_ptr, int threadID, 
                        int PAGESIZE, int INVERT_PAGE_TABLE_SIZE, 
                        int PHYSICAL_MEM_SIZE, int STORAGE_SIZE, 
                        int PAGE_ENTRIES) {
  // init variables
  vm->buffer = buffer;
  vm->storage = storage;
  vm->invert_page_table = invert_page_table;
  vm->sw_table = swap_table;
  vm->pagefault_num_ptr = pagefault_num_ptr;

  // init constants
  vm->thread_id = threadID;
  vm->PAGESIZE = PAGESIZE;
  vm->INVERT_PAGE_TABLE_SIZE = INVERT_PAGE_TABLE_SIZE;
  vm->PHYSICAL_MEM_SIZE = PHYSICAL_MEM_SIZE;
  vm->STORAGE_SIZE = STORAGE_SIZE;
  vm->PAGE_ENTRIES = PAGE_ENTRIES;

  *(vm->pagefault_num_ptr) = 0;

  // before first vm_write or vm_read
  if (vm->thread_id == 0) {
    init_invert_page_table(vm);
    init_sw_table(vm);
  }
}

/* find the minimum value of time stamp which indicates the least recently used entry */
__device__ int find_LRU(VirtualMemory *vm) {
  int min_stamp = vm->invert_page_table[2 * vm->PAGE_ENTRIES];
  int result = 0;
  for (int i = 1; i < vm->PAGE_ENTRIES; i++) {
    if (vm->invert_page_table[2 * vm->PAGE_ENTRIES + i] < min_stamp) {
      min_stamp = vm->invert_page_table[2 * vm->PAGE_ENTRIES + i];
      result = i;
    }
  }
  return result;
}

__device__ uchar vm_read(VirtualMemory *vm, u32 addr) {
  /* Complate vm_read function to read single element from data buffer */
  uchar output = 0;
  u32 page_num = addr / vm->PAGESIZE;   // page number in range [0, 160 * 32 = 5120]
  u32 frame_num;
  u32 physical_address;
  
  // iterate through 1024(10^15 / 10^5 = 1024) page entries.
  for (int i = 0; i < vm->PAGE_ENTRIES; i++) {

    /* page hit */
    if (page_num == vm->invert_page_table[i + vm->PAGE_ENTRIES]) {
      // check the valid bit
      if ((vm->invert_page_table[i] & 0x80000000) != 0x80000000) {
        frame_num = i;    // frame number would be i instead of page_num
        physical_address = (frame_num * vm->PAGESIZE) + (addr & 0x0000001f);  // offset = addr & 0x0000001f(last 5 bits)
        output = vm->buffer[physical_address];
        
        // update the time stamp
        vm->invert_page_table[3 * vm->PAGE_ENTRIES] += 1;
        vm->invert_page_table[frame_num + 2 * vm->PAGE_ENTRIES] = vm->invert_page_table[3 * vm->PAGE_ENTRIES];
        if (vm->invert_page_table[3 * vm->PAGE_ENTRIES + 1] == i) {
          vm->invert_page_table[3 * vm->PAGE_ENTRIES + 1] = find_LRU(vm);
        }

        return output;
      }else{
        /* The valid bit is invalid, load the page from the secondary memory to the physical memory */
        *(vm->pagefault_num_ptr) += 1;
        int secondary_idx1;
        int tr;

        // find the data in the secondary memory according to the page number
        for (tr = 0; tr < (vm->STORAGE_SIZE / vm->PAGESIZE); tr++) {
          if (vm->sw_table[tr] == page_num) {
            secondary_idx1 = tr;
            break;
          }
        }

        // load one page of data from the secondary memory to the physical memory
        for (int k = 0; k < 32; k++) {
          vm->buffer[i * (vm->PAGESIZE) + k] = vm->storage[secondary_idx1 * (vm->PAGESIZE) + k];
        }
        vm->sw_table[secondary_idx1] = 6000;    // update swap table
        output = vm->buffer[(i * vm->PAGESIZE) + (addr & 0x0000001f)];

        vm->invert_page_table[i] &= 0x7fffffff;    // change the invalid bit to valid.

        /* update the time stamp of the page table*/
        vm->invert_page_table[i + 2 * vm->PAGE_ENTRIES] = vm->invert_page_table[3 * vm->PAGE_ENTRIES] + 1;    
        vm->invert_page_table[3 * vm->PAGE_ENTRIES] += 1;
        if (vm->invert_page_table[3 * vm->PAGE_ENTRIES + 1] == i) {
          vm->invert_page_table[3 * vm->PAGE_ENTRIES + 1] = find_LRU(vm);
        }
        return output;
      }
    } 
  }
  /* The page is not in the table: do the swapping */
  *(vm->pagefault_num_ptr) += 1; 
  int swap_idx = vm->invert_page_table[3 * vm->PAGE_ENTRIES + 1];   // select the swap frame index (current)

  /* swap out */
  int tr2, tr3;


  for (tr2 = 0; tr2 < (vm->STORAGE_SIZE / vm->PAGESIZE); tr2++) {
    if (vm->sw_table[tr2] == 6000) {     // find a empty position in the disk
      vm->sw_table[tr2] = vm->invert_page_table[swap_idx + vm->PAGE_ENTRIES];    // update the swap table
      for (tr3 = 0; tr3 < 32; tr3++) { // load the data to the disk
        vm->storage[tr2 * vm->PAGESIZE + tr3] = vm->buffer[swap_idx * vm->PAGESIZE + tr3];
      }
      break;
    }
  }

  /* swap in */
  for (tr3 = 0; tr3 < (vm->STORAGE_SIZE / vm->PAGESIZE); tr3++) {
    if (vm->sw_table[tr3] == page_num) {
      for (tr2 = 0; tr2 < 32; tr2++) {  // load the data to the physical memory
        vm->buffer[swap_idx * vm->PAGESIZE + tr2] = vm->storage[tr3 * vm->PAGESIZE + tr2];
      }
      output = vm->buffer[(swap_idx * vm->PAGESIZE) + (addr & 0x0000001f)];
      vm->invert_page_table[swap_idx + vm->PAGE_ENTRIES] = page_num;  // update page table
      vm->sw_table[tr3] = 6000;
      break;  
    }  
  }

  /* update LRU info */
  vm->invert_page_table[3 * vm->PAGE_ENTRIES] += 1;
  vm->invert_page_table[swap_idx + 2 * vm->PAGE_ENTRIES] = vm->invert_page_table[3 * vm->PAGE_ENTRIES];
  vm->invert_page_table[3 * vm->PAGE_ENTRIES + 1] = find_LRU(vm);

  return output; //TODO
}

__device__ void vm_write(VirtualMemory *vm, u32 addr, uchar value) {
  /* Complete vm_write function to write value into data buffer */
  u32 page_num = addr / vm->PAGESIZE;
  u32 frame_num;
  
  for (int i = 0; i < vm->PAGE_ENTRIES; i++) {

    /* page hit */
    if (page_num == vm->invert_page_table[i + vm->PAGE_ENTRIES]) {
      
      if (!((vm->invert_page_table[i]) >> 31)) {
        frame_num = i;
        vm->buffer[frame_num * vm->PAGESIZE + (addr % vm->PAGESIZE)] = value;

        /* maintain the LRU info */
        vm->invert_page_table[3 * vm->PAGE_ENTRIES] += 1;
        vm->invert_page_table[frame_num + 2 * vm->PAGE_ENTRIES] = vm->invert_page_table[3 * vm->PAGE_ENTRIES];
        if (vm->invert_page_table[3 * vm->PAGE_ENTRIES + 1] == frame_num){
          vm->invert_page_table[3 * vm->PAGE_ENTRIES + 1] = find_LRU(vm);
        }
        return;
      }
      else {
        /* valid bit is set as invalid: load from disk to physical memory */
        *(vm->pagefault_num_ptr) += 1;
        int tr, k;
        int secondary_idx;
        int flag = 0;
        for (tr = 0; tr < (vm->STORAGE_SIZE / vm->PAGESIZE); tr++){
          if (page_num == vm->sw_table[tr]) {
            secondary_idx = tr;
            flag = 1;
            break;
          }
        }

        if (!flag) {
          vm->buffer[i * vm->PAGESIZE + (addr % vm->PAGESIZE)] = value;
        }else{
          // load the data from the disk to the physical memory
          for (k = 0; k < 32; k++){
            vm->buffer[i * (vm->PAGESIZE) + k] = vm->storage[secondary_idx * vm->PAGESIZE + k];
          }
          vm->sw_table[secondary_idx] = 6000;   // update swap table 
          vm->buffer[i * vm->PAGESIZE + (addr % vm->PAGESIZE)] = value;
        }

        vm->invert_page_table[i] = 0x00000000;  // set the invalid bit to valid

        /* maintain the LRU info */
        vm->invert_page_table[3 * vm->PAGE_ENTRIES] += 1;
        vm->invert_page_table[i + 2 * vm->PAGE_ENTRIES] = vm->invert_page_table[3 * vm->PAGE_ENTRIES];
        if (vm->invert_page_table[3 * vm->PAGE_ENTRIES + 1] == i) {
          vm->invert_page_table[3 * vm->PAGE_ENTRIES + 1] = find_LRU(vm);
        }
        return;  
      }
    }
  }

  // check whether the address is an illegel one
  if (addr >= 163840) {
    printf("illegel address");
    return;
  }
  *(vm->pagefault_num_ptr) += 1;
  /* check whether there is empty frame */
  int tr2, tr3;
  int empty_frame;
  for (tr2 = 0; tr2 < vm->PAGE_ENTRIES; tr2++) {
    if ((vm->invert_page_table[tr2] & 0x80000000) == 0x80000000) {
      empty_frame = tr2;
      
      vm->invert_page_table[empty_frame + vm->PAGE_ENTRIES] = page_num;
      vm->invert_page_table[empty_frame] = 0x00000000;  // change the invalid bit to valid
      vm->buffer[(empty_frame * vm->PAGESIZE) + (addr % vm->PAGESIZE)] = value;

      // update LRU info
      vm->invert_page_table[3 * vm->PAGE_ENTRIES] += 1;
      vm->invert_page_table[empty_frame + 2 * vm->PAGE_ENTRIES] = vm->invert_page_table[3 * vm->PAGE_ENTRIES];
      if (vm->invert_page_table[3 * vm->PAGE_ENTRIES + 1] == empty_frame) {
        vm->invert_page_table[3 * vm->PAGE_ENTRIES + 1] = find_LRU(vm);
      }
      return;
    }
  }

  /* no empty frame: swapping */

  int swap_idx = vm->invert_page_table[3 * vm->PAGE_ENTRIES + 1];
  int swap_page = vm->invert_page_table[swap_idx + vm->PAGE_ENTRIES];  
  /* swap out */
  int flag2 = 0;
  for (tr2 = 0; tr2 < (vm->STORAGE_SIZE / vm->PAGESIZE); tr2++) {
    if (vm->sw_table[tr2] == 6000) {
      vm->sw_table[tr2] = swap_page;
      flag2 = 1;
      for (tr3 = 0; tr3 < 32; tr3++) {
        vm->storage[tr2 * vm->PAGESIZE + tr3] = vm->buffer[swap_idx * vm->PAGESIZE + tr3];
      }
      break; 
    }
  }

  /* swap in */
  int flag3 = 0;
  int secondary_idx2;
  for (tr3 = 0; tr3 < (vm->STORAGE_SIZE / vm->PAGESIZE); tr3++) {
    if (vm->sw_table[tr3] == page_num) {
      flag3 = 1;
      secondary_idx2 = tr3;
      for (tr2 = 0; tr2 < 32; tr2++) {
        vm->buffer[swap_idx * vm->PAGESIZE + tr2] = vm->storage[tr3 * vm->PAGESIZE + tr2];
      }
      vm->invert_page_table[swap_idx + vm->PAGE_ENTRIES] = page_num;
      vm->sw_table[tr3] = 6000;
      break;
    }
  }
  
  if (flag2 == 0 && flag3 == 1) {   // both the frame and the secondary memory are full
    vm->sw_table[secondary_idx2] = swap_page;
    for (tr2 = 0; tr2 < 32; tr2++) {
      vm->storage[secondary_idx2 * vm->PAGESIZE + tr2] = vm->buffer[swap_idx * vm->PAGESIZE + tr2];
    } 
  } else if (flag2 == 1 && flag3 == 0) {  // the page does not exist in the secondary memory
    vm->invert_page_table[swap_idx + vm->PAGE_ENTRIES] = page_num;  
  }

  vm->buffer[(swap_idx * vm->PAGESIZE) + (addr % vm->PAGESIZE)] = value;

  /* maintain the LRU info */
  vm->invert_page_table[3 * vm->PAGE_ENTRIES] += 1;
  vm->invert_page_table[2 * vm->PAGE_ENTRIES + swap_idx] = vm->invert_page_table[3 * vm->PAGE_ENTRIES];
  vm->invert_page_table[3 * vm->PAGE_ENTRIES + 1] = find_LRU(vm);

  return;
}

__device__ void vm_snapshot(VirtualMemory *vm, uchar *results, int offset,
                            int input_size) {
  /* Complete snapshot function togther with vm_read to load elements from data
   * to result buffer */
  for (int k = 0; k < input_size; k++) {
    results[k] = vm_read(vm, k + offset);
  }
}

