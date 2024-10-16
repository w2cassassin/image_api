import os
import threading
from dotenv import load_dotenv
from fastapi import FastAPI, File, UploadFile, HTTPException
from PIL import Image, ImageOps, ImageDraw
import io
import pyclamd
from fastapi.responses import JSONResponse
import random
import string
import paramiko
from starlette.concurrency import run_in_threadpool
import aiofiles

# Загрузка переменных из .env
load_dotenv()

app = FastAPI(title="Image Processor")

UPLOAD_DIR = os.getenv("UPLOAD_DIR")  # директория на сервере с апи
LOCAL_SERVER_DOMAIN = os.getenv("LOCAL_SERVER_DOMAIN")  # домен сервера
REMOTE_SERVER = os.getenv("REMOTE_SERVER")  # ip бэкап сервера
REMOTE_PORT = os.getenv("REMOTE_PORT")  # ip бэкап сервера
REMOTE_USER = os.getenv("REMOTE_USER")  # пользователь бэкап сервера
REMOTE_PASSWORD = os.getenv("REMOTE_PASSWORD")  # пользователь бэкап сервера
REMOTE_DIR = os.getenv("REMOTE_DIR")  # директория на бэкап сервере
SSH_KEY_PATH = os.getenv("SSH_KEY_PATH")  # ключ к бэкап серверу
CLAMD_HOST = os.getenv("CLAMD_HOST")  # хост антивируса
CLAMD_PORT = int(os.getenv("CLAMD_PORT"))  # порт антивируса

# Проверка, что директория для загрузки существует
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Инициализация локального хранилища для ClamAV
from threading import local

_thread_local = local()


# Функция отправки файла на удалённый сервер через SCP
def upload_to_remote_server(local_file_path, remote_file_name):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(
            REMOTE_SERVER,
            port=int(REMOTE_PORT),
            username=REMOTE_USER,
            password=REMOTE_PASSWORD,
            timeout=10,
        )

        with ssh.open_sftp() as sftp:
            remote_path = os.path.join(REMOTE_DIR, remote_file_name)
            sftp.put(local_file_path, remote_path)

        ssh.close()
    except Exception as e:
        print(f"Ошибка при отправке на удалённый сервер: {e}")


# Функция для получения clamd клиента (с переиспользованием)
def get_clamd():
    if not hasattr(_thread_local, "clamd"):
        _thread_local.clamd = pyclamd.ClamdNetworkSocket(
            host=CLAMD_HOST, port=CLAMD_PORT
        )
    return _thread_local.clamd


# Функция для проверки на вирусы
async def check_for_viruses(file_content: bytes):
    await run_in_threadpool(_check_for_viruses_sync, file_content)


def _check_for_viruses_sync(file_content: bytes):
    cd = get_clamd()
    if not cd.ping():
        raise HTTPException(status_code=500, detail="Служба ClamAV недоступна")
    scan_result = cd.scan_stream(file_content)
    if scan_result:
        raise HTTPException(status_code=400, detail="Обнаружен вирус в файле")


# Функция сжатия изображения
def compress_image(
    image: Image.Image, target_size_kb: int, output_format: str
) -> io.BytesIO:
    import io
    from PIL import Image

    buffer = io.BytesIO()
    target_size_bytes = target_size_kb * 1024

    if output_format.upper() == "JPEG":
        quality = 90
        while True:
            buffer.seek(0)
            buffer.truncate(0)
            image.save(buffer, format=output_format, quality=quality)
            size = buffer.tell()
            if size <= target_size_bytes or quality <= 10:
                break
            quality -= 10
    elif output_format.upper() == "PNG":
        if image.mode == "RGBA":
            quantized_image = image.quantize(method=Image.Quantize.LIBIMAGEQUANT)
        else:
            quantized_image = image.quantize(
                colors=256, method=Image.Quantize.MEDIANCUT
            )

        buffer.seek(0)
        buffer.truncate(0)
        quantized_image.save(buffer, format=output_format, optimize=True)
        size = buffer.tell()

        if size <= target_size_bytes:
            buffer.seek(0)
            return buffer

        current_width, current_height = image.size
        scaling_factor = (target_size_bytes / size) ** 0.5
        new_width = max(1, int(current_width * scaling_factor))
        new_height = max(1, int(current_height * scaling_factor))
        resized_image = image.resize((new_width, new_height), Image.Resampling.LANCZOS)

        if resized_image.mode != "RGBA":
            quantized_image = resized_image.quantize(
                colors=128, method=Image.Quantize.MEDIANCUT
            )
        else:
            quantized_image = resized_image.quantize(
                method=Image.Quantize.LIBIMAGEQUANT
            )

        buffer.seek(0)
        buffer.truncate(0)
        quantized_image.save(buffer, format=output_format, optimize=True)
        size = buffer.tell()

        if size <= target_size_bytes:
            buffer.seek(0)
            return buffer
    else:
        image.save(buffer, format=output_format)

    buffer.seek(0)
    return buffer


# Функция для генерации имени файла с уникальностью и ограничением на 8 символов
def generate_filename(extension: str, prefix: str) -> str:
    chars = string.ascii_letters + string.digits  # base62
    max_attempts = 5  # Ограничиваем число попыток
    for _ in range(max_attempts):
        random_string = "".join(random.choices(chars, k=5))
        filename = f"{prefix}{random_string}{extension}"  # Общая длина должна быть <=8
        local_file_path = os.path.join(UPLOAD_DIR, filename)
        if not os.path.exists(local_file_path):
            return filename
    raise HTTPException(
        status_code=500, detail="Не удалось создать уникальное имя файла"
    )


# Функция обработки логотипа
def process_logo_image(content: bytes) -> io.BytesIO:
    image = Image.open(io.BytesIO(content))

    # Обрезка до круга
    image = ImageOps.fit(
        image, (min(image.size), min(image.size)), centering=(0.5, 0.5)
    )

    # Создание круглой маски
    mask = Image.new("L", image.size, 0)
    draw = ImageDraw.Draw(mask)
    draw.ellipse((0, 0) + image.size, fill=255)

    # Преобразование изображения в режим RGBA
    image = image.convert("RGBA")

    # Создание изображения с прозрачным фоном
    transparent_image = Image.new("RGBA", image.size)
    transparent_image.paste(image, (0, 0), mask=mask)

    # Сжатие изображения
    compressed_image = compress_image(transparent_image, 100, "PNG")

    return compressed_image


# Функция обработки баннера
def process_banner_image(content: bytes) -> io.BytesIO:
    image = Image.open(io.BytesIO(content))
    image = image.convert("RGB")

    # Сжатие изображения
    compressed_image = compress_image(image, 100, "JPEG")

    return compressed_image


# Эндпоинт для загрузки логотипа
@app.post("/upload_logo/")
async def upload_logo(file: UploadFile = File(...)):
    try:
        if file.content_type not in ["image/jpeg", "image/png"]:
            raise HTTPException(status_code=400, detail="Недопустимый формат файла")

        content = await file.read()

        # Проверка на вирусы асинхронно
        await check_for_viruses(content)

        # Обработка изображения
        compressed_image = await run_in_threadpool(process_logo_image, content)

        # Генерация имени файла
        file_name = generate_filename(".png", "l")
        local_file_path = os.path.join(UPLOAD_DIR, file_name)

        # Сохранение файла
        async with aiofiles.open(local_file_path, "wb") as f:
            await f.write(compressed_image.getvalue())
        threading.Thread(
            target=upload_to_remote_server, args=(local_file_path, file_name)
        ).start()
        # Генерация ссылки на файл
        local_file_url = f"https://{LOCAL_SERVER_DOMAIN}/u/{file_name}"

        return JSONResponse(content={"url": local_file_url})

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка при обработке файла: {e}")


# Эндпоинт для загрузки баннера
@app.post("/upload_banner/")
async def upload_banner(file: UploadFile = File(...)):
    try:
        if file.content_type not in ["image/jpeg", "image/png"]:
            raise HTTPException(status_code=400, detail="Недопустимый формат файла")

        content = await file.read()

        # Проверка на вирусы
        await check_for_viruses(content)

        # Обработка изображения
        compressed_image = await run_in_threadpool(process_banner_image, content)

        # Генерация имени файла
        file_name = generate_filename(".jpg", "b")
        local_file_path = os.path.join(UPLOAD_DIR, file_name)
        # Сохранение файла
        async with aiofiles.open(local_file_path, "wb") as f:
            await f.write(compressed_image.getvalue())

        threading.Thread(
            target=upload_to_remote_server, args=(local_file_path, file_name)
        ).start()
        # Генерация ссылки на файл
        local_file_url = f"https://{LOCAL_SERVER_DOMAIN}/u/{file_name}"

        return JSONResponse(content={"url": local_file_url})

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка при обработке файла: {e}")
