# Исследование метаданных DNS трафика

## Цель работы

1.  Зекрепить практические навыки использования языка программирования R
    для обработки данных
2.  Закрепить знания основных функций обработки данных экосистемы
    tidyverse языка R
3.  Закрепить навыки исследования метаданных DNS трафика

## Ход работы

### Подготовка данных

1.  Импортируйте данные DNS

``` r
library(readr)
library(dplyr)
```


    Присоединяю пакет: 'dplyr'

    Следующие объекты скрыты от 'package:stats':

        filter, lag

    Следующие объекты скрыты от 'package:base':

        intersect, setdiff, setequal, union

``` r
header <- read_csv("header.csv")
```

    Warning: One or more parsing issues, call `problems()` on your data frame for details,
    e.g.:
      dat <- vroom(...)
      problems(dat)

    Rows: 2845 Columns: 1

    ── Column specification ────────────────────────────────────────────────────────
    Delimiter: ","
    chr (1): <!DOCTYPE html>

    ℹ Use `spec()` to retrieve the full column specification for this data.
    ℹ Specify the column types or set `show_col_types = FALSE` to quiet this message.

``` r
header
```

    # A tibble: 2,845 × 1
       `<!DOCTYPE html>`                                                            
       <chr>                                                                        
     1 "<!-- saved from url=(0076)https://github.com/Sofikoshka7/threat_technologie…
     2 "<html lang=\"en\" data-color-mode=\"auto\" data-light-theme=\"light\" data-…
     3 "position: fixed;"                                                           
     4 "display: block;"                                                            
     5 "top: 0;"                                                                    
     6 "left: 0;"                                                                   
     7 "height: 3px;"                                                               
     8 "background: #0076ff;"                                                       
     9 "z-index: 2147483647;"                                                       
    10 "transition:"                                                                
    # ℹ 2,835 more rows

``` r
dns <- read.csv("dns.log",sep ='\t')
```

1.  Добавьте пропущенные данные о структуре данных (назначении столбцов)

``` r
names(dns) <- c("ts","uid","id.orig_h","id.orig_p","id.resp_h","id.resp_p","proto","trans_id","query","qclass","qclass_name","qtype","qtype_name","rcode","rcode_name","AA","TC", "RD","RA","Z","answers","TTLs","rejected")
```

1.  Преобразуйте данные в столбцах в нужный формат
2.  Просмотрите общую структуру данных с помощью функции glimpse()

``` r
dns %>% glimpse()
```

    Rows: 427,934
    Columns: 23
    $ ts          <dbl> 1331901015, 1331901016, 1331901017, 1331901006, 1331901007…
    $ uid         <chr> "C36a282Jljz7BsbGH", "C36a282Jljz7BsbGH", "C36a282Jljz7Bsb…
    $ id.orig_h   <chr> "192.168.202.76", "192.168.202.76", "192.168.202.76", "192…
    $ id.orig_p   <int> 137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 137…
    $ id.resp_h   <chr> "192.168.202.255", "192.168.202.255", "192.168.202.255", "…
    $ id.resp_p   <int> 137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 137…
    $ proto       <chr> "udp", "udp", "udp", "udp", "udp", "udp", "udp", "udp", "u…
    $ trans_id    <int> 57402, 57402, 57402, 57398, 57398, 57398, 62187, 62187, 62…
    $ query       <chr> "HPE8AA67", "HPE8AA67", "HPE8AA67", "WPAD", "WPAD", "WPAD"…
    $ qclass      <chr> "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1"…
    $ qclass_name <chr> "C_INTERNET", "C_INTERNET", "C_INTERNET", "C_INTERNET", "C…
    $ qtype       <chr> "32", "32", "32", "32", "32", "32", "32", "32", "32", "33"…
    $ qtype_name  <chr> "NB", "NB", "NB", "NB", "NB", "NB", "NB", "NB", "NB", "SRV…
    $ rcode       <chr> "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-"…
    $ rcode_name  <chr> "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-"…
    $ AA          <lgl> FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FA…
    $ TC          <lgl> FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FA…
    $ RD          <lgl> TRUE, TRUE, TRUE, TRUE, TRUE, TRUE, TRUE, TRUE, TRUE, FALS…
    $ RA          <lgl> FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FA…
    $ Z           <int> 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0…
    $ answers     <chr> "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-"…
    $ TTLs        <chr> "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-"…
    $ rejected    <lgl> FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FA…

### Анализ

1.  Сколько участников информационного обмена в сети Доброй Организации?

``` r
dns %>% group_by(uid) %>% summarize(total = n()) %>% nrow()
```

    [1] 162495

1.  Какое соотношение участников обмена внутри сети и участников
    обращений к внешним ресурсам?

``` r
dns %>% filter(qtype_name != "A", qtype_name != "AA", qtype_name != "AAA", qtype_name != "AAAA") %>% group_by(uid) %>% summarize(total = n()) %>% nrow() / dns %>% filter(qtype_name == "A"|qtype_name == "AA"| qtype_name == "AAA" | qtype_name == "AAAA") %>% group_by(uid) %>% summarize(total = n()) %>% nrow()
```

    [1] 0.5084645

1.  Найдите топ-10 участников сети, проявляющих наибольшую сетевую
    активность.

``` r
dns %>% select(id.orig_h) %>% group_by(id.orig_h) %>% summarize(total = n()) %>% arrange(desc(total)) %>% head(10)
```

    # A tibble: 10 × 2
       id.orig_h       total
       <chr>           <int>
     1 10.10.117.210   75943
     2 192.168.202.93  26522
     3 192.168.202.103 18121
     4 192.168.202.76  16978
     5 192.168.202.97  16176
     6 192.168.202.141 14967
     7 10.10.117.209   14222
     8 192.168.202.110 13372
     9 192.168.203.63  12148
    10 192.168.202.106 10784

1.  Найдите топ-10 доменов, к которым обращаются пользователи сети и
    соответственное количество обращений.

``` r
top_10 <- dns %>% select(query, qtype_name) %>% filter(qtype_name == "A"|qtype_name == "AA"| qtype_name == "AAA" | qtype_name == "AAAA") %>% group_by(query) %>% summarize(total = n()) %>% arrange(desc(total)) %>% head(10)
top_10
```

    # A tibble: 10 × 2
       query                           total
       <chr>                           <int>
     1 teredo.ipv6.microsoft.com       39273
     2 tools.google.com                14057
     3 www.apple.com                   13390
     4 safebrowsing.clients.google.com 11658
     5 imap.gmail.com                   5543
     6 stats.norton.com                 5537
     7 www.google.com                   5171
     8 ratings-wrs.symantec.com         4464
     9 api.twitter.com                  4348
    10 api.facebook.com                 4137

1.  Опеределите базовые статистические характеристики (функция summary()
    ) интервала времени между последовательным обращениями к топ-10
    доменам.

``` r
summary(diff((dns %>% filter(tolower(query) %in% top_10$query) %>% arrange(ts))$ts))
```

        Min.  1st Qu.   Median     Mean  3rd Qu.     Max. 
        0.00     0.00     0.00     1.08     0.31 49924.53 

1.  Часто вредоносное программное обеспечение использует DNS канал в
    качестве канала управления, периодически отправляя запросы на
    подконтрольный злоумышленникам DNS сервер. По периодическим запросам
    на один и тот же домен можно выявить скрытый DNS канал. Есть ли
    такие IP адреса в исследуемом датасете?

``` r
ip_domain_counts <- dns %>%
  group_by(ip = tolower(id.orig_h), domain = tolower(query)) %>%
  summarise(request_count = n()) %>%
  filter(request_count > 1)
```

    `summarise()` has grouped output by 'ip'. You can override using the `.groups`
    argument.

``` r
unique_ips_with_periodic_requests <- unique(ip_domain_counts$ip)
unique_ips_with_periodic_requests %>% length()
```

    [1] 240

``` r
unique_ips_with_periodic_requests %>% head()
```

    [1] "10.10.10.10"     "10.10.117.209"   "10.10.117.210"   "128.244.37.196" 
    [5] "169.254.109.123" "169.254.228.26" 

### Обогащение данных

1.  Определите местоположение (страну, город) и организацию-провайдера
    для топ-10 доменов. Для этого можно использовать сторонние сервисы,
    например https://v4.ifconfig.co.

-   teredo.ipv6.microsoft.com : США, Редмонд, Microsoft Corporation

-   tools.google.com : США, Моунтайн-Вью, Google LLC

-   www.apple.com : Германия, Франкфурт, Akamai Technologies, Inc.

-   safebrowsing.clients.google.com : США, Моунтайн-Вью, Google LLC

-   imap.gmail.com : США, Истон, Google LLC

-   stats.norton.com : Великобритания Вашингтон, Microsoft Corporation

-   www.google.com : США, Моунтайн-Вью, Google LLC

-   ratings-wrs.symantec.com : США, Редмонд, Microsoft Corporation

-   api.twitter.com : США, Сан-Франциско, Twitter Inc.

-   api.facebook.com : США, Менло-Парк, Facebook, Inc.

## Вывод

Используя программный пакет dplyr, был освоен анализ DNS логов с помощью
языка программирования R.
