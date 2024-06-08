#include<iostream>
#include<cstdlib>
#include<string.h>
#include<time.h>
#include<cmath>


using namespace std;

void tidyup(int vector[],int vector_length,char cod){
	int appo;
	for(int i=0;i<vector_length;i++){
		for(int j=i+1;j<vector_length;j++){
			if(cod=='d'||cod=='D'){
				if(vector[i]<vector[j]){
					appo=vector[i];
					vector[i]=vector[j];
					vector[j]=appo;		
				}
			}else if(cod=='c'||cod=='C'){
				if(vector[i]>vector[j]){
					appo=vector[i];
					vector[i]=vector[j];
					vector[j]=appo;
				}
			}
		}
	}
}

void tidyup_float(float vector[],int vector_length,char cod){
	float appo;
	for(int i=0;i<vector_length;i++){
		for(int j=i+1;j<vector_length;j++){
			if(cod=='d'||cod=='D'){
				if(vector[i]<vector[j]){
					appo=vector[i];
					vector[i]=vector[j];
					vector[j]=appo;		
				}
			}else if(cod=='c'||cod=='C'){
				if(vector[i]>vector[j]){
					appo=vector[i];
					vector[i]=vector[j];
					vector[j]=appo;
				}
			}
		}
	}
}

void populating(int vector[],int vector_length,int min,int max){
	srand(time(NULL));
	for(int i=0;i<vector_length;i++){
		vector[i]=rand()%(max-min+1)+min;
	}
}

void mmm(int vector[],int length,int &max, int &min ,float &media){
   
    media=0;
    min=vector[0];
	max=vector[0];
    for(int i=0;i<length;i++){
        media+=vector[i];
        if(vector[i]<=min)
            min=vector[i];
        if(vector[i]>=max)
            max=vector[i];  
    }
    media/=length;
}

void mmm_float(float vector[],int length,float &max,float &min,float &media){
   
    media=0;
    min=vector[0];
	max=vector[0];
    for(int i=0;i<length;i++){
        media+=vector[i];
        if(vector[i]<=min)
            min=vector[i];
        if(vector[i]>=max)
            max=vector[i];  
    }
    media/=length;
}



void pd_num(int vector[],int l,int pari[],int dispari[]){
	short i=0,j=0;
	for(int k=0; k<l; k++){
		if(vector[k]%2==0){
			pari[i]=vector[k];
			i++;
		}
		else{
			dispari[j]=vector[k];
			j++;
		}
	}	
}

bool dico(int vector[],short l ,short &position,int numeroDaCercare){
	
	bool vf =false;
	position = -1;
    int p = 0, u = l-1, m;
    
        while(p <= u && position == -1)
        {
            m = (p + u) / 2;
            if(numeroDaCercare == vector[m])
            {
                position = m;
            }
            else if(numeroDaCercare < vector[m])
                u = m - 1;
            else
                p = m + 1;
        }
	if(position == -1)
		vf =false;
	else 
		vf=true;
    
	return vf;
}


