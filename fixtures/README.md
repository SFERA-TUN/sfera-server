# Контрольный VP8-ролик

`cover-vp8.ivf` сгенерирован локально из синтетического источника FFmpeg `testsrc2`; стороннее видео не использовалось. Длительность — 2 секунды, 640×360, 30 fps. Это воспроизводимый лабораторный источник, не образец реального звонка.

Команда генерации (FFmpeg с libvpx):

```sh
ffmpeg -hide_banner -loglevel error \
  -f lavfi -i testsrc2=size=640x360:rate=30 -t 2 -an \
  -c:v libvpx -deadline realtime -cpu-used 6 -b:v 1500k -g 30 \
  -f ivf cover-vp8.ivf
```

FFmpeg нужен только для создания нового ролика; сборка и запуск Rust-прототипа используют сохранённый IVF.
