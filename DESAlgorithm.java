import java.lang.*;
import java.util.*;
class DESAlgorithm{
    public static void main(String args[]){
         Scanner sc = new Scanner(System.in);
         int choice = -1;
         while(choice != 0){
            System.out.println("Please enter your choice: Enter 1 for encryption, Enter 2 for decryption, Enter 0 to exit!");
            choice = sc.nextInt();
            if(choice == 1){
                System.out.println("Please Enter the key: ");
                String key_hex = sc.next();
                String key_bin = hextoBin(key_hex);
                List<String> key_after_each_step =  generateKey(key_bin);
                System.out.println("Please Enter the text for encryption: ");
                String input_encryption = sc.next();
                String input_encryption_bin = hextoBin(input_encryption);
                List<String> encryption_after_each_round =  des_encryption(input_encryption_bin,key_after_each_step);
                for(int j=0;j<15;j++){
                    System.out.println("key after iteration "+(j+1)+": "+key_after_each_step.get(j));
                    System.out.println("Plain text after round "+(j+1)+": "+encryption_after_each_round.get(j));
                }
                System.out.println("key after iteration"+16+": "+key_after_each_step.get(15));
                System.out.println("Final encrypted text in binary is: "+ encryption_after_each_round.get(16));
                System.out.println("Final encrypted text in hexadecimal is: "+ bintoHex(encryption_after_each_round.get(16)));

            }
            if(choice == 2){
                System.out.println("Please Enter the key: ");
                String key_hex = sc.next();
                String key_bin = hextoBin(key_hex);
                List<String> key_after_each_step =  generateKey(key_bin);
                System.out.println("Please Enter the text for decryption: ");
                String input_decryption = sc.next();
                String input_decryption_bin = hextoBin(input_decryption);
                List<String> decryption_after_each_round =  des_decryption(input_decryption_bin,key_after_each_step);
                for(int j=0;j<15;j++){
                        System.out.println("key used for decryption is subkey"+(15-j)+": "+key_after_each_step.get(15-j));
                        System.out.println("Cipher text after round"+(j+1)+": "+decryption_after_each_round.get(j));
                }
                System.out.println("key used for decryption is subkey"+0+": "+key_after_each_step.get(0));
                System.out.println("Final decrypted text in binary is: "+ decryption_after_each_round.get(16));
                System.out.println("Final decrypted text in hexadecimal is: "+ bintoHex(decryption_after_each_round.get(16)));
                
            }
            if(choice == 0){
                System.out.println("Exiting the code!");
            }
         }
         sc.close();        
    }
    public static List<String> generateKey(String key_in){
        int shiftArray[] = {1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};
        //permutation 1 to convert 64 bit key to 56 bits
        List<String> key_out = new ArrayList<String>();
        //convert key from 64 bits to 56 bits
        String perm_1 = permutation1_64to56(key_in);
        
        String combine = perm_1;
        for(int i=0;i<16;i++){
            //split key into two halves in each iteration
            String perm1_firstHalf = "";
            String perm1_SecondHalf = "";
        
            for(int j=0;j<28;j++){
                perm1_firstHalf = perm1_firstHalf + combine.charAt(j);
            }
            for(int j=28;j<56;j++){
                perm1_SecondHalf = perm1_SecondHalf + combine.charAt(j);
            }
            
            String key_temp1 = perm1_firstHalf;
            String key_temp2 = perm1_SecondHalf;
            //rotate left first half
            if(shiftArray[i] == 1){
                String left_rotate = rotateLeft(key_temp1);
                key_temp1 = left_rotate;
            }
            if(shiftArray[i] == 2){
                String left_rotate1 = rotateLeft(key_temp1);
                String left_rotate2 = rotateLeft(left_rotate1);
                key_temp1 = left_rotate2;
            }
            //rotate left second half
            if(shiftArray[i] == 1){
                String left_rotate = rotateLeft(key_temp2);
                key_temp2 = left_rotate;
            }
            if(shiftArray[i] == 2){
                String left_rotate1 = rotateLeft(key_temp2);
                String left_rotate2 = rotateLeft(left_rotate1);
                key_temp2 = left_rotate2;
            }
            //combine first half and second half after rotation
            combine = key_temp1 + key_temp2;
            //convert key from 56 to 48 bits
            String  perm_2 = permutation2_56to48(combine);
            key_out.add(perm_2);

        }
        return key_out;

    }

    public static List<String> des_encryption(String input,List<String> key_after_each_step){
        List<String> rounds = new ArrayList<String>();
        String plaintext64bit = permutation3_64to64_initial(input);
        for(int i=0;i<16;i++){
            //split input plain text into two halves in each iteration
            String old_left = "";
            String old_right = "";
        
            for(int j=0;j<32;j++){
                old_left = old_left + plaintext64bit.charAt(j);
            }
            for(int j=32;j<64;j++){
                old_right = old_right + plaintext64bit.charAt(j);
            }
            String new_left = old_right;
            String subkey = key_after_each_step.get(i);
            String result = func_expand_Shring(old_right,subkey);
            String result_perm = permutation6_32to32(result);
            String new_right = func_xor(old_left,result_perm);
            plaintext64bit =  new_left + new_right;
            rounds.add(plaintext64bit);
        }//16 rounds for encryption

        //32 bit swap
        String temp_left = "";
        String temp_right = "";
        temp_left = plaintext64bit.substring(0, 32);
        temp_right = plaintext64bit.substring(32, 64);
        
        String final_left = "";
        final_left = temp_right;
        String final_right = "";
        final_right = temp_left;
        //putting back together left & right
        String final_combine = final_left + final_right;
        //inverse initial permutation & add at last in array named rounds 
        rounds.add(permutation7_64to64_initial_inverse(final_combine));

        return rounds;
    }//function for des encryption


    public static List<String> des_decryption(String input,List<String> key_after_each_step){
        List<String> rounds_dec = new ArrayList<String>();
        //apply the permutation
        String ciphertext64bit = permutation3_64to64_initial(input);
        for(int i=15;i>=0;i--){
            //split input plain text into two halves in each iteration
            String old_left = "";
            String old_right = "";
        
            for(int j=0;j<32;j++){
                old_left = old_left + ciphertext64bit.charAt(j);
            }
            for(int j=32;j<64;j++){
                old_right = old_right + ciphertext64bit.charAt(j);
            }
            String new_left = old_right;
            String subkey = key_after_each_step.get(i);
            String result = func_expand_Shring(old_right,subkey);
            String result_perm = permutation6_32to32(result);
            String new_right = func_xor(old_left,result_perm);
            ciphertext64bit =  new_left + new_right;
            rounds_dec.add(ciphertext64bit);
        }//16 rounds for decryption with keys from 16 to 1

        //32 bit swap
        String temp_left = "";
        String temp_right = "";
        temp_left = ciphertext64bit.substring(0, 32);
        temp_right = ciphertext64bit.substring(32, 64);
        
        String final_left = "";
        final_left = temp_right;
        String final_right = "";
        final_right = temp_left;
        //putting back together left & right
        String final_combine = final_left + final_right;
        //inverse initial permutation & add at last in array named rounds 
        rounds_dec.add(permutation7_64to64_initial_inverse(final_combine));

        return rounds_dec;
    }//function for des decryption

    //function to convert hexadecimal string to binary
    public static String hextoBin(String hex){
        String binary = ""; 
        for(int i=0;i<hex.length();i++){
            char c = hex.charAt(i);
            switch (c) {
                case '0':
                    binary = binary + "0000";
                    break;
                case '1':
                    binary = binary +"0001";
                    break;
                case '2':
                    binary = binary +"0010";
                    break;
                case '3':
                    binary = binary +"0011";
                    break;
                case '4':
                    binary = binary +"0100";
                    break;
                case '5':
                    binary = binary +"0101";
                    break;
                case '6':
                    binary = binary +"0110";
                    break;
                case '7':
                    binary = binary +"0111";
                    break;
                case '8':
                    binary = binary +"1000";
                    break;
                case '9':
                    binary = binary +"1001";
                    break;
                case 'A':
                case 'a':
                    binary = binary +"1010";
                    break;
                case 'B':
                case 'b':
                    binary = binary +"1011";
                    break;
                case 'C':
                case 'c':
                    binary = binary +"1100";
                    break;
                case 'D':
                case 'd':
                    binary = binary +"1101";
                    break;
                case 'E':
                case 'e':
                    binary = binary +"1110";
                    break;
                case 'F':
                case 'f':
                    binary = binary +"1111";
                    break;

        }
    }
        return binary;
    }

    //funcation to convert binary string to hexadecimal
    public static String bintoHex(String bin){
        String hex = "";
        int i = 0;
        Map<String,Character> um = new HashMap<String,Character>();
        um.put("0000", '0');
        um.put("0001", '1');
        um.put("0010", '2');
        um.put("0011", '3');
        um.put("0100", '4');
        um.put("0101", '5');
        um.put("0110", '6');
        um.put("0111", '7');
        um.put("1000", '8');
        um.put("1001", '9');
        um.put("1010", 'A');
        um.put("1011", 'B');
        um.put("1100", 'C');
        um.put("1101", 'D');
        um.put("1110", 'E');
        um.put("1111", 'F');
        while(i < bin.length()){
            String temp = "";
            for(int j=i;j<i+4;j++){
                temp = temp + bin.charAt(j);
            }
            hex = hex + um.get(temp);
            i = i+4;
        } 
        return hex;
    }

    public static String dec_to_bin(int dec){
        String bin = "";
        if(dec == 0){
            bin = bin + "0000";
        }
        if(dec == 1){
            bin = bin + "0001";
        }
        if(dec == 2){
            bin = bin + "0010";
        }
        if(dec == 3){
            bin = bin + "0011";
        }
        if(dec == 4){
            bin = bin + "0100";
        }
        if(dec == 5){
            bin = bin + "0101";
        }
        if(dec == 6){
            bin = bin + "0110";
        }
        if(dec == 7){
            bin = bin + "0111";
        }
        if(dec == 8){
            bin = bin + "1000";
        }
        if(dec == 9){
            bin = bin + "1001";
        }
        if(dec == 10){
            bin = bin + "1010";
        }
        if(dec == 11){
            bin = bin + "1011";
        }
        if(dec == 12){
            bin = bin + "1100";
        }
        if(dec == 13){
            bin = bin + "1101";
        }
        if(dec == 14){
            bin = bin + "1110";
        }
        if(dec == 15){
            bin = bin + "1111";
        }
        return bin;
    }//function for dec to binary

    public static String rotateLeft(String bin){
        int i=1;
        String rotate = "";
        String last = "";
        last = last+bin.charAt(0);
        while(i <= bin.length()-1){
            rotate = rotate + bin.charAt(i);
            i++;
        }
        rotate = rotate + last;
        return rotate;
    }
    public static String permutation1_64to56(String input){
        String output = "";
        int permutationArray[] = new int[56];
        permutationArray[0]=57;
        permutationArray[1]=49;
        permutationArray[2]=41;
        permutationArray[3]=33;
        permutationArray[4]=25;
        permutationArray[5]=17;
        permutationArray[6]=9;
        permutationArray[7]=1;
        permutationArray[8]=58;
        permutationArray[9]=50;
        permutationArray[10]=42;
        permutationArray[11]=34;
        permutationArray[12]=26;
        permutationArray[13]=18;
        permutationArray[14]=10;
        permutationArray[15]=2;
        permutationArray[16]=59;
        permutationArray[17]=51;
        permutationArray[18]=43;
        permutationArray[19]=35;
        permutationArray[20]=27;
        permutationArray[21]=19;
        permutationArray[22]=11;
        permutationArray[23]=3;
        permutationArray[24]=60;
        permutationArray[25]=52;
        permutationArray[26]=44;
        permutationArray[27]=36;
        permutationArray[28]=63;
        permutationArray[29]=55;
        permutationArray[30]=47;
        permutationArray[31]=39;
        permutationArray[32]=31;
        permutationArray[33]=23;
        permutationArray[34]=15;
        permutationArray[35]=7;
        permutationArray[36]=62;
        permutationArray[37]=54;
        permutationArray[38]=46;
        permutationArray[39]=38;
        permutationArray[40]=30;
        permutationArray[41]=22;
        permutationArray[42]=14;
        permutationArray[43]=6;
        permutationArray[44]=61;
        permutationArray[45]=53;
        permutationArray[46]=45;
        permutationArray[47]=37;
        permutationArray[48]=29;
        permutationArray[49]=21;
        permutationArray[50]=13;
        permutationArray[51]=5;
        permutationArray[52]=28;
        permutationArray[53]=20;
        permutationArray[54]=12;
        permutationArray[55]=4;
        for(int i=0;i<56;i++){
            output = output + input.charAt(permutationArray[i]-1);
        }
        return output;
    }
    public static String permutation2_56to48(String input){
        String output = "";
        int permutationArray[] = new int[48];
        permutationArray[0]=14;
        permutationArray[1]=17;
        permutationArray[2]=11;
        permutationArray[3]=24;
        permutationArray[4]=1;
        permutationArray[5]=5;
        permutationArray[6]=3;
        permutationArray[7]=28;
        permutationArray[8]=15;
        permutationArray[9]=6;
        permutationArray[10]=21;
        permutationArray[11]=10;
        permutationArray[12]=23;
        permutationArray[13]=19;
        permutationArray[14]=12;
        permutationArray[15]=4;
        permutationArray[16]=26;
        permutationArray[17]=8;
        permutationArray[18]=16;
        permutationArray[19]=7;
        permutationArray[20]=27;
        permutationArray[21]=20;
        permutationArray[22]=13;
        permutationArray[23]=2;
        permutationArray[24]=41;
        permutationArray[25]=52;
        permutationArray[26]=31;
        permutationArray[27]=37;
        permutationArray[28]=47;
        permutationArray[29]=55;
        permutationArray[30]=30;
        permutationArray[31]=40;
        permutationArray[32]=51;
        permutationArray[33]=45;
        permutationArray[34]=33;
        permutationArray[35]=48;
        permutationArray[36]=44;
        permutationArray[37]=49;
        permutationArray[38]=39;
        permutationArray[39]=56;
        permutationArray[40]=34;
        permutationArray[41]=53;
        permutationArray[42]=46;
        permutationArray[43]=42;
        permutationArray[44]=50;
        permutationArray[45]=36;
        permutationArray[46]=29;
        permutationArray[47]=32;
        for(int i=0;i<48;i++){
            output = output + input.charAt(permutationArray[i]-1);
        }
        return output;
    }
    public static String permutation3_64to64_initial(String input){
        String output = "";
        int permutationArray[] = new int[64];
        permutationArray[0]=58;
        permutationArray[1]=50;
        permutationArray[2]=42;
        permutationArray[3]=34;
        permutationArray[4]=26;
        permutationArray[5]=18;
        permutationArray[6]=10;
        permutationArray[7]=2;
        permutationArray[8]=60;
        permutationArray[9]=52;
        permutationArray[10]=44;
        permutationArray[11]=36;
        permutationArray[12]=28;
        permutationArray[13]=20;
        permutationArray[14]=12;
        permutationArray[15]=4;
        permutationArray[16]=62;
        permutationArray[17]=54;
        permutationArray[18]=46;
        permutationArray[19]=38;
        permutationArray[20]=30;
        permutationArray[21]=22;
        permutationArray[22]=14;
        permutationArray[23]=6;
        permutationArray[24]=64;
        permutationArray[25]=56;
        permutationArray[26]=48;
        permutationArray[27]=40;
        permutationArray[28]=32;
        permutationArray[29]=24;
        permutationArray[30]=16;
        permutationArray[31]=8;
        permutationArray[32]=57;
        permutationArray[33]=49;
        permutationArray[34]=41;
        permutationArray[35]=33;
        permutationArray[36]=25;
        permutationArray[37]=17;
        permutationArray[38]=9;
        permutationArray[39]=1;
        permutationArray[40]=59;
        permutationArray[41]=51;
        permutationArray[42]=43;
        permutationArray[43]=35;
        permutationArray[44]=27;
        permutationArray[45]=19;
        permutationArray[46]=11;
        permutationArray[47]=3;
        permutationArray[48]=61;
        permutationArray[49]=53;
        permutationArray[50]=45;
        permutationArray[51]=37;
        permutationArray[52]=29;
        permutationArray[53]=21;
        permutationArray[54]=13;
        permutationArray[55]=5;
        permutationArray[56]=63;
        permutationArray[57]=55;
        permutationArray[58]=47;
        permutationArray[59]=39;
        permutationArray[60]=31;
        permutationArray[61]=23;
        permutationArray[62]=15;
        permutationArray[63]=7;
        for(int i=0;i<64;i++){
            output = output + input.charAt(permutationArray[i]-1);
        }
        return output;
    }

    public static String permutation4_32to48(String input){
        String output = "";
        int permutationArray[] = new int[48];
        permutationArray[0]=32;
        permutationArray[1]=1;
        permutationArray[2]=2;
        permutationArray[3]=3;
        permutationArray[4]=4;
        permutationArray[5]=5;
        permutationArray[6]=4;
        permutationArray[7]=5;
        permutationArray[8]=6;
        permutationArray[9]=7;
        permutationArray[10]=8;
        permutationArray[11]=9;
        permutationArray[12]=8;
        permutationArray[13]=9;
        permutationArray[14]=10;
        permutationArray[15]=11;
        permutationArray[16]=12;
        permutationArray[17]=13;
        permutationArray[18]=12;
        permutationArray[19]=13;
        permutationArray[20]=14;
        permutationArray[21]=15;
        permutationArray[22]=16;
        permutationArray[23]=17;
        permutationArray[24]=16;
        permutationArray[25]=17;
        permutationArray[26]=18;
        permutationArray[27]=19;
        permutationArray[28]=20;
        permutationArray[29]=21;
        permutationArray[30]=20;
        permutationArray[31]=21;
        permutationArray[32]=22;
        permutationArray[33]=23;
        permutationArray[34]=24;
        permutationArray[35]=25;
        permutationArray[36]=24;
        permutationArray[37]=25;
        permutationArray[38]=26;
        permutationArray[39]=27;
        permutationArray[40]=28;
        permutationArray[41]=29;
        permutationArray[42]=28;
        permutationArray[43]=29;
        permutationArray[44]=30;
        permutationArray[45]=31;
        permutationArray[46]=32;
        permutationArray[47]=1;
           
        for(int i=0;i<48;i++){
            output = output + input.charAt(permutationArray[i]-1);
        }
        return output;
    }
 
    public static String permutation5_48to32_sbox(String input){
        String output = "";
        String input_8_part[] = new String[8];
        int i=0;
        int x=0;
        input_8_part[0] = input.substring(0, 6);
        input_8_part[1] = input.substring(6, 12);
        input_8_part[2] = input.substring(12, 18);
        input_8_part[3] = input.substring(18, 24);
        input_8_part[4] = input.substring(24, 30);
        input_8_part[5] = input.substring(30, 36);
        input_8_part[6] = input.substring(36, 42);
        input_8_part[7] = input.substring(42, 48);
        
        int s1[][] = new int[4][16];
        s1[0][0] = 14; s1[1][0] = 0; s1[2][0] = 4; s1[3][0] = 15;  
        s1[0][1] = 4;  s1[1][1] = 15;  s1[2][1] = 1;  s1[3][1] = 12;
        s1[0][2] = 13; s1[1][2] = 7; s1[2][2] = 14; s1[3][2] = 8; 
        s1[0][3] = 1;  s1[1][3] = 4; s1[2][3] = 8; s1[3][3] = 2;
        s1[0][4] = 2;  s1[1][4] = 14; s1[2][4] = 13; s1[3][4] = 4;
        s1[0][5] = 15; s1[1][5] = 2; s1[2][5] = 6; s1[3][5] = 9;
        s1[0][6] = 11; s1[1][6] = 13; s1[2][6] = 2; s1[3][6] = 1;
        s1[0][7] = 8;  s1[1][7] = 1; s1[2][7] = 11; s1[3][7] = 7;
        s1[0][8] = 3;  s1[1][8] = 10; s1[2][8] = 15; s1[3][8] = 5;
        s1[0][9] = 10; s1[1][9] = 6; s1[2][9] = 12; s1[3][9] = 11;
        s1[0][10] = 6; s1[1][10] = 12; s1[2][10] = 9; s1[3][10] = 3;
        s1[0][11] = 12; s1[1][11] = 11; s1[2][11] = 7; s1[3][11] = 14;
        s1[0][12] = 5; s1[1][12] = 9; s1[2][12] = 3; s1[3][12] = 10;
        s1[0][13] = 9; s1[1][13] = 5; s1[2][13] = 10; s1[3][13] = 0;
        s1[0][14] = 0; s1[1][14] = 3; s1[2][14] = 5; s1[3][14] = 6;
        s1[0][15] = 7; s1[1][15] = 8; s1[2][15] = 0; s1[3][15] = 13;

        int s2[][] = new int[4][16];
        s2[0][0] = 15; s2[1][0] = 3; s2[2][0] = 0; s2[3][0] = 13;  
        s2[0][1] = 1;  s2[1][1] = 13;  s2[2][1] = 14;  s2[3][1] = 8;
        s2[0][2] = 8; s2[1][2] = 4; s2[2][2] = 7; s2[3][2] = 10; 
        s2[0][3] = 14;  s2[1][3] = 7; s2[2][3] = 11; s2[3][3] = 1;
        s2[0][4] = 6;  s2[1][4] = 15; s2[2][4] = 10; s2[3][4] = 3;
        s2[0][5] = 11; s2[1][5] = 2; s2[2][5] = 4; s2[3][5] = 15;
        s2[0][6] = 3; s2[1][6] = 8; s2[2][6] = 13; s2[3][6] = 4;
        s2[0][7] = 4;  s2[1][7] = 14; s2[2][7] = 1; s2[3][7] = 2;
        s2[0][8] = 9;  s2[1][8] = 12; s2[2][8] = 5; s2[3][8] = 11;
        s2[0][9] = 7; s2[1][9] = 0; s2[2][9] = 8; s2[3][9] = 6;
        s2[0][10] = 2; s2[1][10] = 1; s2[2][10] = 12; s2[3][10] = 7;
        s2[0][11] = 13; s2[1][11] = 10; s2[2][11] = 6; s2[3][11] = 12;
        s2[0][12] = 12; s2[1][12] = 6; s2[2][12] = 9; s2[3][12] = 0;
        s2[0][13] = 0; s2[1][13] = 9; s2[2][13] = 3; s2[3][13] = 5;
        s2[0][14] = 5; s2[1][14] = 11; s2[2][14] = 2; s2[3][14] = 14;
        s2[0][15] = 10; s2[1][15] = 5; s2[2][15] = 15; s2[3][15] = 9;

        int s3[][] = new int[4][16];
        s3[0][0] = 10; s3[1][0] = 13; s3[2][0] = 13; s3[3][0] = 1;  
        s3[0][1] = 0;  s3[1][1] = 7;  s3[2][1] = 6;  s3[3][1] = 10;
        s3[0][2] = 9; s3[1][2] = 0; s3[2][2] = 4; s3[3][2] = 13; 
        s3[0][3] = 14;  s3[1][3] = 9; s3[2][3] = 9; s3[3][3] = 0;
        s3[0][4] = 6;  s3[1][4] = 3; s3[2][4] = 8; s3[3][4] = 6;
        s3[0][5] = 3; s3[1][5] = 4; s3[2][5] = 15; s3[3][5] = 9;
        s3[0][6] = 15; s3[1][6] = 6; s3[2][6] = 3; s3[3][6] = 8;
        s3[0][7] = 5;  s3[1][7] = 10; s3[2][7] = 0; s3[3][7] = 7;
        s3[0][8] = 1;  s3[1][8] = 2; s3[2][8] = 11; s3[3][8] = 4;
        s3[0][9] = 13; s3[1][9] = 8; s3[2][9] = 1; s3[3][9] = 15;
        s3[0][10] = 12; s3[1][10] = 5; s3[2][10] = 2; s3[3][10] = 14;
        s3[0][11] = 7; s3[1][11] = 14; s3[2][11] = 12; s3[3][11] = 3;
        s3[0][12] = 11; s3[1][12] = 12; s3[2][12] = 5; s3[3][12] = 11;
        s3[0][13] = 4; s3[1][13] = 11; s3[2][13] = 10; s3[3][13] = 5;
        s3[0][14] = 2; s3[1][14] = 15; s3[2][14] = 14; s3[3][14] = 2;
        s3[0][15] = 8; s3[1][15] = 1; s3[2][15] = 7; s3[3][15] = 12;
        
        int s4[][] = new int[4][16];
        s4[0][0] = 7; s4[1][0] = 13; s4[2][0] = 10; s4[3][0] = 3;  
        s4[0][1] = 13;  s4[1][1] = 8;  s4[2][1] = 6;  s4[3][1] = 15;
        s4[0][2] = 14; s4[1][2] = 11; s4[2][2] = 9; s4[3][2] = 0; 
        s4[0][3] = 3;  s4[1][3] = 5; s4[2][3] = 0; s4[3][3] = 6;
        s4[0][4] = 0;  s4[1][4] = 6; s4[2][4] = 12; s4[3][4] = 10;
        s4[0][5] = 6; s4[1][5] = 15; s4[2][5] = 11; s4[3][5] = 1;
        s4[0][6] = 9; s4[1][6] = 0; s4[2][6] = 7; s4[3][6] = 13;
        s4[0][7] = 10;  s4[1][7] = 3; s4[2][7] = 13; s4[3][7] = 8;
        s4[0][8] = 1;  s4[1][8] = 4; s4[2][8] = 15; s4[3][8] = 9;
        s4[0][9] = 2; s4[1][9] = 7; s4[2][9] = 1; s4[3][9] = 4;
        s4[0][10] = 8; s4[1][10] = 2; s4[2][10] = 3; s4[3][10] = 5;
        s4[0][11] = 5; s4[1][11] = 12; s4[2][11] = 14; s4[3][11] = 11;
        s4[0][12] = 11; s4[1][12] = 1; s4[2][12] = 5; s4[3][12] = 12;
        s4[0][13] = 12; s4[1][13] = 10; s4[2][13] = 2; s4[3][13] = 7;
        s4[0][14] = 4; s4[1][14] = 14; s4[2][14] = 8; s4[3][14] = 2;
        s4[0][15] = 15; s4[1][15] = 9; s4[2][15] = 4; s4[3][15] = 14;

        int s5[][] = new int[4][16];
        s5[0][0] = 2; s5[1][0] = 14; s5[2][0] = 4; s5[3][0] = 11;  
        s5[0][1] = 12;  s5[1][1] = 11;  s5[2][1] = 2;  s5[3][1] = 8;
        s5[0][2] = 4; s5[1][2] = 2; s5[2][2] = 1; s5[3][2] = 12; 
        s5[0][3] = 1;  s5[1][3] = 12; s5[2][3] = 11; s5[3][3] = 7;
        s5[0][4] = 7;  s5[1][4] = 4; s5[2][4] = 10; s5[3][4] = 1;
        s5[0][5] = 10; s5[1][5] = 7; s5[2][5] = 13; s5[3][5] = 14;
        s5[0][6] = 11; s5[1][6] = 13; s5[2][6] = 7; s5[3][6] = 2;
        s5[0][7] = 6;  s5[1][7] = 1; s5[2][7] = 8; s5[3][7] = 13;
        s5[0][8] = 8;  s5[1][8] = 5; s5[2][8] = 15; s5[3][8] = 6;
        s5[0][9] = 5; s5[1][9] = 0; s5[2][9] = 9; s5[3][9] = 15;
        s5[0][10] = 3; s5[1][10] = 15; s5[2][10] = 12; s5[3][10] = 0;
        s5[0][11] = 15; s5[1][11] = 10; s5[2][11] = 5; s5[3][11] = 9;
        s5[0][12] = 13; s5[1][12] = 3; s5[2][12] = 6; s5[3][12] = 10;
        s5[0][13] = 0; s5[1][13] = 9; s5[2][13] = 3; s5[3][13] = 4;
        s5[0][14] = 14; s5[1][14] = 8; s5[2][14] = 0; s5[3][14] = 5;
        s5[0][15] = 9; s5[1][15] = 6; s5[2][15] = 14; s5[3][15] = 3;

        int s6[][] = new int[][]{{12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},
                                 {10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},
                                 {9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},
                                 {4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13}};

        int s7[][] = new int[][]{{4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},
                                 {13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},
                                 {1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},
                                 {6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}};

        int s8[][] = new int[][]{{13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},
                                 {1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},
                                 {7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},
                                 {2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}};

        

        for(int k=0;k<8;k++){
            String row_bin = "" + input_8_part[k].charAt(0) + input_8_part[k].charAt(5);
            String col_bin = "" + input_8_part[k].charAt(1) + input_8_part[k].charAt(2) + input_8_part[k].charAt(3) + input_8_part[k].charAt(4);
            
            int row=-1;
            int col=-1;
            if(row_bin.equals("00")){
                row = 0;
            }
            if(row_bin.equals("01")){
                row = 1;
            }
            if(row_bin.equals("10")){
                row = 2;
            }
            if(row_bin.equals("11")){
                row = 3;
            }
            if(col_bin.equals("0000")){
                col = 0;
            }
            if(col_bin.equals("0001")){
                col = 1;
            }
            if(col_bin.equals("0010")){
                col = 2;
            }
            if(col_bin.equals("0011")){
                col = 3;
            }
            if(col_bin.equals("0100")){
                col = 4;
            }
            if(col_bin.equals("0101")){
                col = 5;
            }
            if(col_bin.equals("0110")){
                col = 6;
            }
            if(col_bin.equals("0111")){
                col = 7;
            }
            if(col_bin.equals("1000")){
                col = 8;
            }
            if(col_bin.equals("1001")){
                col = 9;
            }
            if(col_bin.equals("1010")){
                col = 10;
            }
            if(col_bin.equals("1011")){
                col = 11;
            }
            if(col_bin.equals("1100")){
                col = 12;
            }
            if(col_bin.equals("1101")){
                col = 13;
            }
            if(col_bin.equals("1110")){
                col = 14;
            }
            if(col_bin.equals("1111")){
                col = 15;
            }

            //choose s boxe for each input part and shrink the shrink, then store in output
            if(k+1 == 1){
                String temp = dec_to_bin(s1[row][col]);
                output = output + temp;
            }
            if(k+1 == 2){
                String temp = dec_to_bin(s2[row][col]);
                output = output + temp;
            }
            if(k+1 == 3){
                String temp = dec_to_bin(s3[row][col]);
                output = output + temp;
            }
            if(k+1 == 4){
                String temp = dec_to_bin(s4[row][col]);
                output = output + temp;
            }
            if(k+1 == 5){
                String temp = dec_to_bin(s5[row][col]);
                output = output + temp;
            }
            if(k+1 == 6){
                String temp = dec_to_bin(s6[row][col]);
                output = output + temp;
            }
            if(k+1 == 7){
                String temp = dec_to_bin(s7[row][col]);
                output = output + temp;
            }
            if(k+1 == 8){
                String temp = dec_to_bin(s8[row][col]);
                output = output + temp;
            }

        }
        
        return output;
        
        }//function for s box permutation where each s box takes 6 bits input and convert to 4 bit output
    

    public static String permutation6_32to32(String input){
            String output = "";
            int permutationArray[] = {16,7,20,21,29,12,28,17,1 ,15,23,26,5,18 ,31,10,2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25};
            for(int i=0;i<32;i++){
                output = output + input.charAt(permutationArray[i]-1);
            }
            return output;
    }

    public static String permutation7_64to64_initial_inverse(String input){
        String output = "";
        int permutationArray[] = {40,8,48,16,56,24,64,32,
                                  39,7,47,15,55,23,63,31,
                                  38,6,46,14,54,22,62,30,
                                  37,5,45,13,53,21,61,29,
                                  36,4,44,12,52,20,60,28,
                                  35,3,43,11,51,19,59,27,
                                  34,2,42,10,50,18,58,26,
                                  33,1,41,9,49,17,57,25};
        for(int i=0;i<64;i++){
            output = output + input.charAt(permutationArray[i]-1);
        }
        return output;
    }//function to inverse initial permutation

    public static String func_xor(String input1,String input2){
        String ans = "";
        if(input1.length() == input2.length()){
            int x = 0;
            while(x<input1.length()){
                if(input1.charAt(x) == input2.charAt(x)){
                    ans = ans + "0";
                }
                if(input1.charAt(x) != input2.charAt(x)){
                    ans = ans + "1";
                }
                x++;
            }
        }   
        return ans;
    }//function to perform xor operation

    public static String func_expand_Shring(String old_right,String subkey){
        String ans = "";
        String padded_permutation = permutation4_32to48(old_right);
        String temp = func_xor(padded_permutation, subkey);
        ans = permutation5_48to32_sbox(temp);
        return ans;
    }//function to expand 32 bits to 48 bits, xor padded output with subkey, then perform sbox permutation

}