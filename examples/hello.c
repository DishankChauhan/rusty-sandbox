#include <stdio.h>
#include <stdlib.h>

int main() {
    printf("Hello from C in the rusty-sandbox!\n");
    
    // Test memory allocation
    int *array = malloc(10 * sizeof(int));
    if (array) {
        for (int i = 0; i < 10; i++) {
            array[i] = i * i;
        }
        
        printf("Squares: ");
        for (int i = 0; i < 10; i++) {
            printf("%d ", array[i]);
        }
        printf("\n");
        
        free(array);
    }
    
    return 0;
}