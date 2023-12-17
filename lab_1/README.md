# LAB1
Разаков Дамир

# Информационно-аналитические технологии поиска угроз информационной безопасности

## Лабораторная работа №1

## Цель работы

1.  Повысить уровень практического мастерства в использовании языка
    программирования R для обработки данных.
2.  Улучшить профессиональные навыки работы с Rstudio IDE:
    -   Мастерски овладеть установкой пакетов в Rstudio.
    -   Искусно взаимодействовать с проектами в Rstudio.
    -   Компетентно настраивать и работать с Git в Rstudio.
3.  Укрепить основные знания о базовых типах данных языка R и научиться
    выполнять простейшие операции с ними.

## План

Используя программный пакет swirl, освоить базовые операции в языке
программирования R.

## Ход работы

``` r
5+7
```

    [1] 12

``` r
x <-5+7
x
```

    [1] 12

``` r
y <-x-3
y
```

    [1] 9

``` r
z<-c(1.1,9,3.14)
z
```

    [1] 1.10 9.00 3.14

``` r
z<-555
c(z,555,z)
```

    [1] 555 555 555

``` r
z*2+100
```

    [1] 1210

``` r
my_sqrt<-sqrt(z-1)
my_sqrt
```

    [1] 23.5372

``` r
my_div <- z / my_sqrt
z * 2 + 1000
```

    [1] 2110

## 2 | In this lesson, you will learn how to inspect your local workspace in R and begin to explore

## the relationship between your workspace and your machine’s file system.

``` r
getwd()
```

    [1] "C:/Users/RR/Documents"

``` r
ls()
```

    [1] "has_annotations" "my_div"          "my_sqrt"         "x"              
    [5] "y"               "z"              

``` r
x<-9
ls()
```

    [1] "has_annotations" "my_div"          "my_sqrt"         "x"              
    [5] "y"               "z"              

``` r
list.files()
```

     [1] "4a games"            "Battlefield 4"       "desktop.ini"        
     [4] "Downloads"           "DyingLight"          "IISExpress"         
     [7] "Klei"                "lab_1.qmd"           "lab_1.rmarkdown"    
    [10] "My Games"            "My Music"            "My Pictures"        
    [13] "My Videos"           "My Web Sites"        "Overwatch"          
    [16] "Paradox Interactive" "Visual Studio 2022" 

``` r
?list.files
```

    запускаю httpd сервер помощи... готово

``` r
args(list.files)
```

    function (path = ".", pattern = NULL, all.files = FALSE, full.names = FALSE, 
        recursive = FALSE, ignore.case = FALSE, include.dirs = FALSE, 
        no.. = FALSE) 
    NULL

``` r
old.dir <- getwd()
dir.create("testdir")
setwd("testdir")
file.create("mytest.R")
```

    [1] TRUE

``` r
list.files
```

    function (path = ".", pattern = NULL, all.files = FALSE, full.names = FALSE, 
        recursive = FALSE, ignore.case = FALSE, include.dirs = FALSE, 
        no.. = FALSE) 
    .Internal(list.files(path, pattern, all.files, full.names, recursive, 
        ignore.case, include.dirs, no..))
    <bytecode: 0x000002bafeb44940>
    <environment: namespace:base>

``` r
file.exists("mytest.R")
```

    [1] TRUE

``` r
file.info("mytest.R")
```

             size isdir mode               mtime               ctime
    mytest.R    0 FALSE  666 2023-12-17 05:27:33 2023-12-17 05:27:33
                           atime exe
    mytest.R 2023-12-17 05:27:33  no

``` r
file.rename("mytest.R","mytest2.R")
```

    [1] TRUE

``` r
file.copy("mytest2.R", "mytest3.R")
```

    [1] TRUE

``` r
file.path("mytest3.R")
```

    [1] "mytest3.R"

``` r
file.path("folder1", "folder2")
```

    [1] "folder1/folder2"

``` r
dir.create(file.path("testdir2","testdir3"),recursive = TRUE)
setwd(old.dir)
```

## 3 | Now we wll learn how to create sequences of numbers in R.

``` r
1:20
```

     [1]  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 16 17 18 19 20

``` r
pi:10
```

    [1] 3.141593 4.141593 5.141593 6.141593 7.141593 8.141593 9.141593

``` r
15:1
```

     [1] 15 14 13 12 11 10  9  8  7  6  5  4  3  2  1

``` r
seq(1,20)
```

     [1]  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 16 17 18 19 20

``` r
seq(0, 10, by=0.5)
```

     [1]  0.0  0.5  1.0  1.5  2.0  2.5  3.0  3.5  4.0  4.5  5.0  5.5  6.0  6.5  7.0
    [16]  7.5  8.0  8.5  9.0  9.5 10.0

``` r
seq(5, 10, length=30)
```

     [1]  5.000000  5.172414  5.344828  5.517241  5.689655  5.862069  6.034483
     [8]  6.206897  6.379310  6.551724  6.724138  6.896552  7.068966  7.241379
    [15]  7.413793  7.586207  7.758621  7.931034  8.103448  8.275862  8.448276
    [22]  8.620690  8.793103  8.965517  9.137931  9.310345  9.482759  9.655172
    [29]  9.827586 10.000000

``` r
my_seq <- seq(5, 10, length=30)
length(my_seq)
```

    [1] 30

``` r
1:length(my_seq)
```

     [1]  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25
    [26] 26 27 28 29 30

``` r
seq(along.with = my_seq)
```

     [1]  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25
    [26] 26 27 28 29 30

``` r
seq_along(my_seq)
```

     [1]  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25
    [26] 26 27 28 29 30

``` r
rep(0, times = 40)
```

     [1] 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
    [39] 0 0

``` r
rep(c(0, 1, 2), times = 10)
```

     [1] 0 1 2 0 1 2 0 1 2 0 1 2 0 1 2 0 1 2 0 1 2 0 1 2 0 1 2 0 1 2

``` r
rep(c(0, 1, 2), each = 10)
```

     [1] 0 0 0 0 0 0 0 0 0 0 1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2

## 4 | The vector, being the simplest and most commonly used data structure in R, is widely renowned..

``` r
num_vect <- c(0.5,55,-10,6)
num_vect < 1
```

    [1]  TRUE FALSE  TRUE FALSE

``` r
tf <- num_vect < 1
tf
```

    [1]  TRUE FALSE  TRUE FALSE

``` r
num_vect >= 6
```

    [1] FALSE  TRUE FALSE  TRUE

``` r
my_char <- c("My","name","is")
my_char
```

    [1] "My"   "name" "is"  

``` r
paste(my_char, collapse = " ")
```

    [1] "My name is"

``` r
c(my_char, "Damir")
```

    [1] "My"    "name"  "is"    "Damir"

``` r
my_name <- c(my_char, "Damir")
my_name
```

    [1] "My"    "name"  "is"    "Damir"

``` r
paste(my_name,collapse = " ")
```

    [1] "My name is Damir"

``` r
paste("Hello", "world!", sep = " ")
```

    [1] "Hello world!"

``` r
paste(1:3, c("X", "Y", "Z"), sep = "")
```

    [1] "1X" "2Y" "3Z"

``` r
paste(LETTERS, 1:4, sep = "-")
```

     [1] "A-1" "B-2" "C-3" "D-4" "E-1" "F-2" "G-3" "H-4" "I-1" "J-2" "K-3" "L-4"
    [13] "M-1" "N-2" "O-3" "P-4" "Q-1" "R-2" "S-3" "T-4" "U-1" "V-2" "W-3" "X-4"
    [25] "Y-1" "Z-2"

------------------------------------------------------------------------

## Quarto

Quarto enables you to weave together content and executable code into a
finished document. To learn more about Quarto see <https://quarto.org>.

## Running Code

When you click the **Render** button a document will be generated that
includes both content and the output of embedded code. You can embed
code like this:

``` r
1 + 1
```

    [1] 2

You can add options to executable code like this

    [1] 4

The `echo: false` option disables the printing of code (only output is
displayed).
