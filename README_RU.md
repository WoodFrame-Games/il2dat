# HypperDump

Консольная C++-утилита для полной автоматической обработки защищённого IL2CPP-билда
(Hypper Sandbox 0.5.0.7, Unity 6000.0.74f1, IL2CPP v31, упаковщик PGL armor).

Инструмент, начиная прямо с **APK**:

1. извлекает `lib/arm64-v8a/libil2cpp.so` из base/split APK (ZIP, stored + deflate);
2. эмулирует распаковщик (ARM64, через Unicorn) и снимает образ runtime-памяти
   (heap + сегменты библиотеки);
3. собирает **чистую `global-metadata.dat`** из расшифрованных чанков;
4. находит настоящие `Il2CppCodeGenModule` (95 модулей) прямо в сегментах;
5. строит runtime ELF с настоящим `Il2CppCodeRegistration` + `Il2CppMetadataRegistration`,
   символами `g_CodeRegistration` / `g_MetadataRegistration` и починенными `Il2CppType`;
6. строит карту методов `real_method_pointers.tsv`;
7. (опционально) запускает Cpp2IL и получает реальные тела методов (ISIL).

## Сборка

Нужен MinGW-w64 (MSYS2 `ucrt64`): `g++`, `zlib`. Unicorn уже лежит в
`third_party/unicorn` (`unicorn.dll` + заголовки).

```
build.bat            -> dist\hypperdump.exe (+ unicorn.dll)
```

или через CMake:

```
cmake -S . -B build -G Ninja
cmake --build build
```

## Запуск

```
hypperdump full --out out_dir --apk base.apk --apk split_arm64.apk
hypperdump full --out out_dir --so libil2cpp.so
```

Полезные опции:

| Опция | Значение |
|---|---|
| `--apk <path>` | APK (можно несколько: base + split). `.so` берётся автоматически |
| `--so <path>` | напрямую указать `libil2cpp.so` (или `.apk`) |
| `--out <dir>` | каталог для артефактов |
| `--cpp2il <exe>` | путь к `Cpp2IL.exe` — после сборки ELF выполнить ISIL-дамп |
| `--segments <dir>` | переиспользовать уже снятый образ памяти (без эмуляции) |
| `--seconds N` | лимит времени эмуляции (по умолчанию 360) |
| `--verbose` | подробный лог эмуляции |

### Артефакты в `--out`

| Файл | Описание |
|---|---|
| `libil2cpp.so` | извлечённый бинарь (если вход был APK) |
| `global-metadata.dat` | чистая метадата v31 |
| `libil2cpp.runtime.so` | runtime ELF с настоящим `CodeRegistration` |
| `real_method_pointers.tsv` | карта 80 926 методов |
| `chunks.txt`, `heap_end.bin`, `memseg_*.bin` | образ памяти (для повторного запуска / отладки) |
| `isil_dump/` | реальные тела методов (если задан `--cpp2il`) |

### Пример с Cpp2IL

```
hypperdump full --out out --apk base.apk --apk split_arm64.apk ^
    --cpp2il "third_party\cpp2il\Cpp2IL.exe"
```

Вручную (эквивалентно):

```
Cpp2IL.exe --force-binary-path out\libil2cpp.runtime.so ^
    --force-metadata-path out\global-metadata.dat ^
    --force-unity-version 6000.0.74f1 ^
    --output-as isil --output-to out\isil_dump
```

## Проверка корректности (0.5.0.7)

Артефакты, полученные инструментом из APK, побайтово совпадают с эталонными:

| Артефакт | SHA-256 |
|---|---|
| `global-metadata.dat` | `0C92800BE376C60652137EA11215F2EC5B73D523DC0A12C41686C7C0CBF6612E` |
| `real_method_pointers.tsv` | `055DCABE8505AB17650A8FC01D7E745247358C9D1D14231E3081BA0E16B353A2` |

`libil2cpp.runtime.so` совпадает по размеру (`93 683 712`) и структуре; незначительные
отличия в сегментах 3/5 — это runtime-хендлы типов, которые всё равно нормализуются
шагом «починка Il2CppType».

## Архитектура

```
src/bytes.hpp      - little-endian хелперы, чтение/запись файлов
src/elf.{hpp,cpp}  - разбор ELF64: program headers, dynamic, symtab, RELA
src/zip.{hpp,cpp}  - чтение ZIP/APK (stored + deflate через zlib)
src/emulator.*     - ARM64-эмулятор распаковщика на Unicorn (PLT-заглушки, SVC, хук
                     неотображённых страниц, сбор чанков-копий метадаты)
src/metadata.*     - сборка/разбор global-metadata.dat v31
src/codereg.*      - поиск модулей, сборка runtime ELF, карта методов
src/main.cpp       - CLI
```

## Ограничения

- `unicorn.dll` — внешняя зависимость (кроме системных DLL больше ничего);
  линкуется из `third_party/unicorn`. Сам Unicorn — библиотека с C-API.
- Эмуляция завершается по достижении полного набора чанков метадаты
  (детерминированно) или по таймауту.
- Особенности бинаря (адрес `il2cpp_init`, триггер `mprotect`, смещение PH5)
  заданы в `EmuOptions`; для других версий их нужно обновить.