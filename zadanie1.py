import struct
from colorama import init, Fore, Back, Style

init(autoreset=True)
#DUMP_FILE = "C:/Users/Эрик/Desktop/Файлы/dumpik.bin"
print("Введите путь до файла: ")
DUMP_FILE = input().replace("\\", "/")
def print_colored(text, color=Fore.WHITE, style=Style.NORMAL):
    """Печать цветного текста"""
    print(f"{style}{color}{text}")


def parse_mbr_structure(data):
    """Парсим структуру MBR"""
    if len(data) < 512:
        print_colored(f"⚠ Файл меньше 512 байт ({len(data)} байт)", Fore.YELLOW)
        return

    print_colored("Таблица смещений сектора", Fore.CYAN, style=Style.BRIGHT)


    # Сектор 0 (MBR)
    print_colored("\nСектор 0 (MBR / Защитный MBR):", Fore.BLUE, style=Style.BRIGHT)
    print_colored(f"   Смещение: 0x00000000 - 0x000001FF (0-511 байт)", Fore.WHITE)
    print_colored(f"   Размер: 512 байт", Fore.WHITE)
    print_colored(f"   LBA: 0", Fore.WHITE)

    # Детали MBR
    print_colored(f"\n   Байты 0-445: Код загрузчика", Fore.GREEN)
    print_colored(f"      Смещение: 0x00000000 - 0x000001BD", Fore.LIGHTBLACK_EX)

    print_colored(f"\n   Байты 446-509: Таблица разделов (4 записи)", Fore.GREEN)
    print_colored(f"      Смещение: 0x000001BE - 0x000001FD", Fore.LIGHTBLACK_EX)

    # Парсим записи разделов
    print_colored(f"\n   Записи разделов:", Fore.MAGENTA)
    for i in range(4):
        start = 446 + i * 16
        entry = data[start:start + 16]
        type_code = entry[4]

        if type_code != 0:
            lba_start = struct.unpack('<I', entry[8:12])[0]
            sectors = struct.unpack('<I', entry[12:16])[0]
            lba_end = lba_start + sectors - 1

            active = "🔴 Активный" if entry[0] == 0x80 else "⚪ Неактивный"

            print_colored(f"\n     Раздел {i + 1}:", Fore.YELLOW)
            print_colored(f"       Статус: {active}", Fore.WHITE)
            print_colored(f"       Тип: 0x{type_code:02X}", Fore.CYAN)
            print_colored(f"       LBA начало: {lba_start}", Fore.GREEN)
            print_colored(f"       LBA конец: {lba_end}", Fore.GREEN)
            print_colored(f"       Секторов: {sectors}", Fore.GREEN)
            print_colored(f"       Размер: {(sectors * 512) / (1024 ** 3):.2f} ГБ", Fore.GREEN)
            print_colored(f"       Смещение в файле: 0x{lba_start * 512:08X}", Fore.LIGHTBLUE_EX)
        else:
            print_colored(f"\n     Раздел {i + 1}: 🚫 ПУСТОЙ", Fore.LIGHTBLACK_EX)

    print_colored(f"\n   Байты 510-511: Сигнатура", Fore.GREEN)
    print_colored(f"      Смещение: 0x000001FE - 0x000001FF", Fore.LIGHTBLACK_EX)
    signature = f"{data[510]:02X} {data[511]:02X}"
    if data[510] == 0x55 and data[511] == 0xAA:
        print_colored(f"      Значение: {signature} ✅ ВАЛИДНАЯ", Fore.GREEN)
    else:
        print_colored(f"      Значение: {signature} ❌ НЕВАЛИДНАЯ", Fore.RED)


def print_hex_dump_with_colors(data, sector_num=0):
    print_colored(f"\nHEX-Дамп сектора {sector_num}:", Fore.MAGENTA, style=Style.BRIGHT)
    print_colored("Смещение  00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F  ASCII", Fore.CYAN)
    print_colored("-" * 70, Fore.LIGHTBLACK_EX)

    sector_start = sector_num * 512
    sector_data = data[sector_start:sector_start + 512]

    for i in range(0, len(sector_data), 16):
        offset = sector_start + i

        hex_bytes = []
        for j in range(16):
            if i + j < len(sector_data):
                b = sector_data[i + j]

                if offset + j == 510 or offset + j == 511:  # Сигнатура
                    color = Fore.GREEN if b == 0x55 or b == 0xAA else Fore.RED
                elif 446 <= offset + j <= 509:  # Таблица разделов
                    color = Fore.YELLOW
                elif offset + j < 446:  # Код загрузчика
                    color = Fore.BLUE
                else:
                    color = Fore.WHITE

                hex_bytes.append(f"{color}{b:02X}{Style.RESET_ALL}")
            else:
                hex_bytes.append("  ")

        # ASCII представление
        ascii_chars = []
        for j in range(16):
            if i + j < len(sector_data):
                b = sector_data[i + j]
                if 32 <= b <= 126:  # Печатные символы
                    ascii_chars.append(chr(b))
                else:
                    ascii_chars.append("·")
            else:
                ascii_chars.append(" ")

        # Группируем hex байты по 8
        hex_line = ""
        for k in range(0, 16, 8):
            hex_line += " ".join(hex_bytes[k:k + 8]) + "  "

        print(f"{offset:08X}  {hex_line} {''.join(ascii_chars)}")


def analyze_gpt_structure(data):
    """Анализ GPT структуры"""

    if len(data) >= 1024:
        # Проверяем второй сектор (LBA 1)
        gpt_header = data[512:1024]

        # GPT сигнатура
        if gpt_header[0:8] == b'EFI PART':
            print_colored("✅ Обнаружена GPT структура", Fore.GREEN, style=Style.BRIGHT)

            # Читаем GPT заголовок
            print_colored("\nGPT заголовок (LBA 1):", Fore.YELLOW)
            print_colored(f"   Смещение: 0x00000200 - 0x000003FF", Fore.WHITE)
            print_colored(f"   Сигнатура: 'EFI PART'", Fore.WHITE)

            # LBA таблицы разделов
            partition_entry_lba = struct.unpack('<Q', gpt_header[72:80])[0]
            num_partitions = struct.unpack('<I', gpt_header[80:84])[0]
            partition_size = struct.unpack('<I', gpt_header[84:88])[0]

            print_colored(f"\n   Параметры GPT:", Fore.MAGENTA)
            print_colored(f"      LBA таблицы разделов: {partition_entry_lba}", Fore.WHITE)
            print_colored(f"      Количество разделов: {num_partitions}", Fore.WHITE)
            print_colored(f"      Размер записи раздела: {partition_size} байт", Fore.WHITE)

            # Таблица разделов GPT (обычно LBA 2-33)
            print_colored(f"\nТаблица разделов GPT:", Fore.BLUE, style=Style.BRIGHT)
            for i in range(min(5, num_partitions)):  # Первые 5 разделов
                lba_start = partition_entry_lba + i
                offset = lba_start * 512

                if offset + partition_size <= len(data):
                    partition_data = data[offset:offset + partition_size]

                    # Тип раздела GUID (первые 16 байт)
                    type_guid = partition_data[0:16]
                    guid_str = "-".join([
                        type_guid[3::-1].hex(),
                        type_guid[5:3:-1].hex(),
                        type_guid[7:5:-1].hex(),
                        type_guid[8:10].hex(),
                        type_guid[10:16].hex()
                    ]).upper()

                    # LBA начала раздела
                    first_lba = struct.unpack('<Q', partition_data[32:40])[0]
                    last_lba = struct.unpack('<Q', partition_data[40:48])[0]

                    if first_lba != 0:
                        print_colored(f"\n   Раздел {i + 1}:", Fore.YELLOW)
                        print_colored(f"      Смещение в файле: 0x{offset:08X}", Fore.LIGHTBLUE_EX)
                        print_colored(f"      LBA: {first_lba} - {last_lba}", Fore.GREEN)
                        print_colored(f"      Секторов: {last_lba - first_lba + 1}", Fore.GREEN)
                        print_colored(f"      Размер: {(last_lba - first_lba + 1) * 512 / (1024 ** 3):.2f} ГБ",
                                      Fore.GREEN)
                        print_colored(f"      Тип GUID: {guid_str[:36]}...", Fore.CYAN)
        else:
            print_colored("❌ GPT структура не обнаружена", Fore.RED)


def print_file_structure(data):
    """Общая структура файла"""
    file_size = len(data)
    num_sectors = file_size // 512

    print_colored("Структура файла:", Fore.CYAN, style=Style.BRIGHT)

    print_colored(f"\nРазмер файла: {file_size} байт", Fore.WHITE)
    print_colored(f"Полных секторов: {num_sectors}", Fore.WHITE)
    print_colored(f"Остаток: {file_size % 512} байт", Fore.WHITE)

    # Таблица секторов
    print_colored("\nТаблица секторов:", Fore.MAGENTA, style=Style.BRIGHT)

    for i in range(min(10, num_sectors)):  # Первые 10 секторов
        sector_start = i * 512
        sector_end = sector_start + 511

        # Проверяем тип сектора
        sector_data = data[sector_start:sector_start + 512]

        if i == 0:
            label = "MBR / Защитный MBR"
            color = Fore.BLUE
        elif i == 1 and sector_data[0:8] == b'EFI PART':
            label = "GPT Заголовок"
            color = Fore.GREEN
        elif i >= 2 and i <= 33:
            label = "GPT Разделы"
            color = Fore.YELLOW
        else:
            # Проверяем что в секторе
            non_zero = sum(1 for b in sector_data if b != 0)
            if non_zero == 0:
                label = "Пустой"
                color = Fore.LIGHTBLACK_EX
            elif non_zero < 10:
                label = "Мало данных"
                color = Fore.LIGHTYELLOW_EX
            else:
                label = "Данные"
                color = Fore.WHITE

        print_colored(f"\nСектор {i:3d} (LBA {i:3d}):", color)
        print_colored(f"   Смещение: 0x{sector_start:08X} - 0x{sector_end:08X}", Fore.LIGHTBLACK_EX)
        print_colored(f"   Описание: {label}", color)

        # Быстрая информация о содержимом
        if i == 0 and len(sector_data) >= 512:
            sig = f"{sector_data[510]:02X}{sector_data[511]:02X}"
            print_colored(f"   Сигнатура: {sig}",
                          Fore.GREEN if sig == "55AA" else Fore.RED)


def main():
    try:

        with open(DUMP_FILE, 'rb') as f:
            # Читаем достаточно для анализа
            data = f.read(1024 * 16)  # 16KB для анализа

        if len(data) < 512:
            print_colored(f"⚠ Файл слишком маленький ({len(data)} байт)", Fore.YELLOW)
            return

        # 1. Общая структура
        print_file_structure(data)

        # 2. Анализ MBR
        parse_mbr_structure(data)

        # 3. Hex дамп первого сектора
        print_hex_dump_with_colors(data, 0)

        # 4. Проверка GPT
        analyze_gpt_structure(data)

        # 5. Дополнительные секторы
        if len(data) >= 1024:
            print_colored("Следующие секторы:", Fore.CYAN, style=Style.BRIGHT)

            for sector in [1, 2, 3]:
                if sector * 512 < len(data):
                    sector_data = data[sector * 512:(sector + 1) * 512]
                    non_zero = sum(1 for b in sector_data if b != 0)

                    print_colored(f"\nСектор {sector} (LBA {sector}):", Fore.WHITE)
                    print_colored(f"   Ненулевых байт: {non_zero}/512",
                                  Fore.GREEN if non_zero > 0 else Fore.LIGHTBLACK_EX)

                    # Показываем первые 16 байт
                    first_bytes = " ".join(f"{b:02X}" for b in sector_data[:16])
                    print_colored(f"   Первые байты: {first_bytes}", Fore.CYAN)


    except FileNotFoundError:
        print_colored(f"\nОшибка: Файл '{DUMP_FILE}' не найден!", Fore.RED, style=Style.BRIGHT)
        print_colored("Проверь путь к файлу!", Fore.YELLOW)
    except Exception as e:
        print_colored(f"\nОШИБКА: {e}", Fore.RED)


if __name__ == "__main__":
    main()
    input()