all: build run

build:
		docker build -t bashscan .

run: 
		docker run --rm -it bashscan "$@"
