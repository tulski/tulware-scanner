<h1 align="center">
  tulware-scanner
</h1>
<p align="center">
  Prosty Antywirus dla systemu z jądrem Linux
</p>

![ELO](https://img.shields.io/badge/!-IMPORTANT!-red)

**DISCLAIMER**: This software is for educational purposes only. The author is not responsible for its use. It's a very simple software created as a project for a university.

# Założenia

Aplikacja napisana przede wszystkim z myślą o systemie operacyjny Linux w architekturze x86_64 (zarówno wersja 32 jak i 64 bitowa). Działanie zostało sprawdzone również na systemie macOs Big Sur 11.5.2.

Aplikacja jest prostą implementacją oprogramowania antywirusowego. Niebezpieczne pliki wykrywa przez porównywanie ich skrótów z bazą skrótów. 

Do liczenia skrótów skorzystałem z funkcji skrótu SHA-256. Główną motywacją było jego szerokie użycie na rynku. Przeglądając internet bardzo często spotykamy się z sygnaturami SHA-256. To może być pomóc w populacji bazy danych skrótami niebezpiecznych plików. Odpalając skanowanie na większym zasobie danych nie zauwżyłem różnic czasowych między różnymi algorytmami.

# Mechanizm kwarantanny

Aplikacja podczas wykrycia potencjalnie niebezpiecznego pliku:

1. przenosi potencjalnie niebezpieczny plik do odpowiedniego katalogu stanowiącego kwarantannę tj. `"/var/tmp/tulware-quarantine"`,
2. zmienia uprawnienia pliku na zerowe,
3. w oryginalnej lokalizacji tworzy łącze symboliczne do pliku w kwarantannie

# Instrukcja uruchomienia

```bash
$ git clone https://github.com/tulski/tulware-scanner.git
$ cd tulware-scanner
$ ./tulware-scanner -h
tulware scanner

Usage:
  tulware-scanner -d <directory> [-f <file>]
  tulware-scanner -h

Options:
  -h                Show this screen.
  -d <directory>    Directory path to scan. [default="."]
  -f <file>         File to scan
```

# Działanie programu

```bash

$ ./tulware-scanner -d "./files-to-scan"                  
 SIGNATURE RECOGNIZED | 49f47eaab00dd3d2b6c6aef1bba2d87fd069fb6e6067fe8bf9636019ef0f377e | ./files-to-scan/pan-tadeusz.txt
 SIGNATURE RECOGNIZED | da8bf15b389f23953c844cbd173a68a0b70613bb146b4fc586d87b7308b96811 | ./files-to-scan/folder_1/folder_2/wirus.txt
 SIGNATURE RECOGNIZED | 2f293f67aa33f2ce247b28d6fb2fef2623cfde731f96b3d7f84ae74e9e192bdd | ./files-to-scan/folder_1/malware.txt
 -------------------- | abf32c0733b1682315706c1dc2a474413bbdf8f0dbbb3741a12856595f1e84cf | ./files-to-scan/some_text_file.txt
```

Struktura katalogu `./files-to-scan` przed uruchomieniem aplikacji.
```bash
$ tree -l 10             
▁ 
/Users/tulski/CLionProjects/tulus/files-to-scan
├── folder_1
|  ├── folder_2
|  |  └── wirus.txt
|  └── malware.txt
├── pan-tadeusz.txt
└── some_text_file.txt

directory: 2 file: 4

```
Struktura katalogu `./files-to-scan` po uruchomieniu aplikacji.
```bash
$ tree -l 10
▁ 
/Users/tulski/CLionProjects/tulus/files-to-scan
├── folder_1
|  ├── folder_2
└── some_text_file.txt

directory: 2 file: 1 symboliclink: 3
```

# Analiza statyczna

Podczas rozwijania aplikacji korzystałem z środowska Clion i narzędzia clang-tidy. Oba rozwiązania w połączeniu pozwoliły mi ustrzec się przed głupimi problemami wynikającymi z niedoświadczenia.

# Analiza przecieków pamięci

```bash
$ leaks -atExit -- ./tulware-scanner      
 SIGNATURE RECOGNIZED | 49f47eaab00dd3d2b6c6aef1bba2d87fd069fb6e6067fe8bf9636019ef0f377e | ./files-to-scan_1/pan-tadeusz.txt
 SIGNATURE RECOGNIZED | da8bf15b389f23953c844cbd173a68a0b70613bb146b4fc586d87b7308b96811 | ./files-to-scan_1/folder_1/folder_2/wirus.txt
 SIGNATURE RECOGNIZED | 2f293f67aa33f2ce247b28d6fb2fef2623cfde731f96b3d7f84ae74e9e192bdd | ./files-to-scan_1/folder_1/malware.txt
 -------------------- | abf32c0733b1682315706c1dc2a474413bbdf8f0dbbb3741a12856595f1e84cf | ./files-to-scan_1/some_text_file.txt
 ...

Process 89582 is not debuggable. Due to security restrictions, leaks can only show or save contents of readonly memory of restricted processes.

Process:         tulware-scanner [89582]
Path:            /Users/USER/*/tulware-scanner
Load Address:    0x1046a4000
Identifier:      tulware-scanner
Version:         ???
Code Type:       ARM64
Platform:        macOS
Parent Process:  leaks [89581]

Date/Time:       2022-04-15 20:34:32.333 +0200
Launch Time:     2022-04-15 20:34:31.701 +0200
OS Version:      macOS 11.5.2 (20G95)
Report Version:  7
Analysis Tool:   /usr/bin/leaks

Physical footprint:         6817K
Physical footprint (peak):  6817K
----

leaks Report Version: 4.0
Process 89582: 213 nodes malloced for 16 KB
Process 89582: 0 leaks for 0 total leaked bytes.
```

Przy użyciu kilku narzędzi analizowałem kod pod kątem potencjalnych wycieków pamięci. Nie udało mi się żadnego znaleźć.
