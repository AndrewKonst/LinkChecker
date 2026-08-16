# LinkChecker

CLI-утилита для проверки ссылок в Markdown-файлах: рекурсивно находит `.md` файлы, парсит их через `markdown-it-py`, проверяет локальные пути, `file://` и HTTP/HTTPS ссылки (параллельно, с кэшем по URL) и выводит цветной отчёт о битых ссылках.

## Установка

```bash
python3 -m pip install -r requirements.txt
```

## Запуск

```bash
python3 checker.py ./my-project
python3 checker.py https://github.com/user/repo.git
```
