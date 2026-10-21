"""启动本地 S-AES 实验台：python app.py [--port 8766]，然后用浏览器打开 http://127.0.0.1:8766"""

from saes.server import main

if __name__ == "__main__":
    main()
