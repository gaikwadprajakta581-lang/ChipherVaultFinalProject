
class White
{
int num;
White(int x)
{
num=x;
}
}
class Red extends White
{
Red(int y)
{
super(y);
}
void display()
{
System.out.println("Value of num "+num);
}
}
class Blue extends Red
{
int b;
Blue(int z)
{
super(z);
b=z;
}
}
class MultipleInheritance
{
public static void main(String []args)
{
Blue b1= new Blue(96);
b1.display();
System.out.println("Value of B="+b1.b);
}
}