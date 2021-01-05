#include <cstdio>
using namespace std;

int main(){
    FILE* fin = fopen("log/a.txt", "w");
    if (fin == NULL){
        printf("Error\n");
    }
    printf("%ld\n", (long)fin);
    return 0;
}

