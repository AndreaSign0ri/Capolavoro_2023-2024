#include <iostream>
#include<cstdlib>
#include<ctime>
#include<cmath>

using namespace std;

void di_che_tipo_e(short x1,short x2,short x3,short y1 ,short y2,short y3){

	int l1,l2,l3,rett;

	l1 = sqrt(pow(x1+x2,2)+pow(y1+y2,2)) ;
	l2 = sqrt(pow(x2+x3,2)+pow(y2+y3,2)) ;
	l3 = sqrt(pow(x1+x3,2)+pow(y1+y3,2)) ;
	
	
	if(l1==l2 && l1==l3)
		cout << "Il triangolo e' equilatero";
	else if(l1==l2 || l1==l3||l2==l3)
		cout << "Il triangolo e' isoscele";
	else if (l1>l2 && l1>l3 && l1<(l2+l3)||l2>l1 && l2>l3 && l2<(l1+l3)||l3>l2 && l3>l1 && l3<(l1+l2))
		cout << "Il triangolo e' rettangolo "<<endl;
	else 
		cout << "Il triangolo e' scaleno";
}

int main(){	
	short x1,y1,x2,y2,x3,y3;
	cout << "Inserisci il primo punto"<<endl;
	cin  >> x1 >>y1; 
	cout << "Inserisci il secondo punto"<<endl;
	cin  >> x2 >>y2; 
	cout << "Inserisci il terzo punto"<<endl;
	cin  >> x3 >>y3; 
	
	di_che_tipo_e(x1,x2,x3,y1,y2,y3);
	
	return 0;
}
