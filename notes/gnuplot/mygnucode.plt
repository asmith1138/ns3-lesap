set terminal pdf
set output "gnuplot.pdf"
set title "Drivers Data"
set xlabel "Number of Driver"
set ylabel "Drivers Info"
plot "mydata.txt" using 1:2 with impulse title "Speed km/hr" lw 2,"mydata.txt" using 1:3 with points title "Age" lw 2

set terminal png size 600,400
set output "gnuplotsalary.png"
set title "Drivers Data"
set xlabel "Number of Driver"
set ylabel "Drivers Salary"
plot "mydata.txt" using 1:4 with linespoints title "Salary in Rs." lw 2, 20000 title "Minimum Salary"
