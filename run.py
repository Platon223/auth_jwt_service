from service import create_service

app = create_service()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5555, debug=True)