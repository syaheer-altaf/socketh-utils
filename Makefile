HEADER_PATH = ./bin/headers
SRC_PATH = ./bin
OUTPUT_DIR = .

compile:
	gcc $(SRC_PATH)/test_packets.c -o $(OUTPUT_DIR)/test -I$(HEADER_PATH)
	sudo chown root $(OUTPUT_DIR)/test
	sudo chmod u+s $(OUTPUT_DIR)/test
	gcc $(SRC_PATH)/arpspoof.c -o $(OUTPUT_DIR)/arpspoof -I$(HEADER_PATH)
	sudo chown root $(OUTPUT_DIR)/arpspoof
	sudo chmod u+s $(OUTPUT_DIR)/arpspoof
	gcc $(SRC_PATH)/dqsniff.c -o $(OUTPUT_DIR)/dqsniff -I$(HEADER_PATH)
	sudo chown root $(OUTPUT_DIR)/dqsniff
	sudo chmod u+s $(OUTPUT_DIR)/dqsniff

clean:
	sudo rm -f $(OUTPUT_DIR)/test $(OUTPUT_DIR)/arpspoof $(OUTPUT_DIR)/dqsniff

