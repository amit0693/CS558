#!/usr/bin/env python3
import math
import sys
class RC6:
    def __init__(self):
        self.W = 32
        self.R = 20
        self.b = 0
        self.log_w = int(math.log2(self.W))
        self.modulo = pow(2,self.W)
        self.S = [0] * (2*self.R + 4)


    def parseInputFile(self,inputFile):
        lineNum = 0
        for line in inputFile:
            if lineNum == 0:
                line = line.lower()
                mode = line.strip()
            elif lineNum == 1:
                text = line.split(":")[1]
            elif lineNum == 2:
                userKey = line.split(":")[1]
            else:
                print("Invalid input file format Invalid line\n")
                sys.exit(1)
            lineNum += 1
        return mode, text, userKey

    def makeEndian(self , key):
        endian = ""
        if len(key) %2 != 0:
            key = "0" + key
        for i in range(len(key)-1, -1, -2):
            endian += key[i-1]
            endian += key[i]
        return endian

    def rightShift(self, a: int, b: int) -> int:
        b <<= self.W - self.log_w
        b >>= self.W - self.log_w
        return (a >> b) | (a << (self.W - b)) 

    def leftShift(self, a: int, b: int) -> int:
        a = int(a)
        b <<= self.W - self.log_w
        b >>= self.W - self.log_w
        return (a << b) | (a >> (self.W - b)) 

    def keySchedule(self, key):

        wBytes = math.ceil(float(self.W)/8)
        c = math.ceil((len(key)) / wBytes)
        L = [0x00]*c
        for i in range(c):
            start = wBytes * 2 * i
            end = start + wBytes * 2
            L.append(self.makeEndian(key[start:end]))

        p = math.ceil((math.e - 2) * pow(2, self.W))
        q = (1.618033988749895 - 1) * pow(2, self.W) 

        self.S[0] = p
        for i in range(0,(2*self.R+3)+1):
            self.S[i] = (self.S[i] + q) % self.modulo
        i = j = A = B = 0
        v = 3*max(c,(2*self.R + 4))
        for temp in range(1,v+1):
            A = self.S[i] = self.leftShift((self.S[i] + A + B) % self.modulo, 3)
            B = L[j] = self.leftShift((L[j] + A + B) % self.modulo, (A+B)%self.W)
            i = (i + 1) % (2 * self.R + 4)
            j = (j + 1) % c

    def hexToString(self , a,b,c,d):
        strA = self.makeEndian('{:04x}'.format(a))
        strB = self.makeEndian('{:04x}'.format(a))
        strC = self.makeEndian('{:04x}'.format(a))
        strD = self.makeEndian('{:04x}'.format(a))
        result = strA + strB + strC + strD

        return result

    def decrypt(self,text):
        A = int(self.makeEndian(text[:8]),16)
        B = int(self.makeEndian(text[8:16]),16)
        C = int(self.makeEndian(text[16:24]),16)
        D = int(self.makeEndian(text[24:32]),16)
        
        C -= self.S[2 * self.R + 3]
        A -= self.S[2 * self.R + 2]
        for i in range(self.R,0,-1):

            A, B, C, D = D, A, B, C
            u = self.leftShift((D * (2 * D + 1)) % self.modulo , self.log_w)
            t = self.leftShift((B * (2 * B + 1)) % self.modulo, self.log_w)
            tmod = t % self.W
            umod = u % self.W
            C = self.rightShift((C - self.S[2 * i + 1]) % self.modulo , tmod) ^ u
            A = self.rightShift((A - self.S[2 * i]) % self.modulo , umod) ^ t
        
        D -= self.S[1]
        B -= self.S[0]

        result = self.hexToString(A, B, C, D)

        return result


    def encrypt(self, text):
    
        A = int(self.makeEndian(text[:8]),16)
        B = int(self.makeEndian(text[8:16]),16)
        C = int(self.makeEndian(text[16:24]),16)
        D = int(self.makeEndian(text[24:32]),16)

        B += (self.S[0])
        D += (self.S[1])
        for i in range(1,self.R+1):
            t = self.leftShift((B * (2 * B + 1)) % self.modulo, self.log_w)
            u = self.leftShift((D * (2 * D + 1)) % self.modulo, self.log_w)
            tmod = t % self.W
            umod = u % self.W
            A = (self.leftShift((A ^ t), umod) + self.S[2 * i]) % self.modulo
            C = (self.leftShift((C ^ u), tmod) + self.S[2 * i + 1]) % self.modulo
            A, B, C, D = B , C , D , A

        A = (A + self.S[2 * self.R + 2])
        C = (C + self.S[2 * self.R + 3])

        result = self.hexToString(A, B, C, D)

        return result

    def main(self):

        if len(sys.argv) != 3:
            print("Incorrect number of arguments!!!\n")
            print( "usage: run INPUT OUTPUT\n")
            return 0

        try:
            inputFile = open(sys.argv[1], 'r')
        except OSError:
            print("Could not open/read input file:", sys.argv[1])
            sys.exit(1)

        mode, text, userKey = self.parseInputFile(inputFile)
        text = text.replace(" ","")
        userKey = userKey.replace(" ","")
        result = ""
        self.b = len(userKey)//2
        self.keySchedule(userKey)
        if mode == "encryption":
            temp_result = self.encrypt(text)
        else:
            temp_result = self.decrypt(text)
        for i in range(0,len(temp_result),2):
            result += temp_result[i:i+2] + " "

        try:
            outputFile = open(sys.argv[2], 'w+')
        except OSError:
            print("Could not open output file:", sys.argv[2])
            return 0
        if mode == "encryption":
            outputFile.write("ciphertext: "+result)
        else:
            outputFile.write("plaintext: "+result)
        
        inputFile.close()
        outputFile.close()

if __name__ == '__main__':
    r = RC6()
    r.main()
