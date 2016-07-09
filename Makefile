packet_capture: main.o
	g++ -o packet_capture main.o -lpcap

main.o: main.cpp
	g++ -c -o main.o main.cpp

clean:
	rm -f ./*.o
	rm -f ./packet_capture
