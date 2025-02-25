pragma circom 2.1.5;

include "@zk-email/zk-regex-circom/circuits/regex_helpers.circom";

// regex: [a-zA-Z0-9-._]+&#064;[a-zA-Z0-9-.]+(\n|.)+for (=\n)?[a-zA-Z._]+\.
template IgMail(msg_bytes) {
	signal input msg[msg_bytes];
	signal output out;

	var num_bytes = msg_bytes+1;
	signal in[num_bytes];
	in[0]<==255;
	for (var i = 0; i < msg_bytes; i++) {
		in[i+1] <== msg[i];
	}

	component eq[102][num_bytes];
	component lt[30][num_bytes];
	component and[109][num_bytes];
	component multi_or[24][num_bytes];
	signal states[num_bytes+1][25];
	signal states_tmp[num_bytes+1][25];
	signal from_zero_enabled[num_bytes+1];
	from_zero_enabled[num_bytes] <== 0;
	component state_changed[num_bytes];

	for (var i = 1; i < 25; i++) {
		states[0][i] <== 0;
	}

	for (var i = 0; i < num_bytes; i++) {
		state_changed[i] = MultiOR(24);
		states[i][0] <== 1;
		lt[0][i] = LessEqThan(8);
		lt[0][i].in[0] <== 65;
		lt[0][i].in[1] <== in[i];
		lt[1][i] = LessEqThan(8);
		lt[1][i].in[0] <== in[i];
		lt[1][i].in[1] <== 90;
		and[0][i] = AND();
		and[0][i].a <== lt[0][i].out;
		and[0][i].b <== lt[1][i].out;
		lt[2][i] = LessEqThan(8);
		lt[2][i].in[0] <== 97;
		lt[2][i].in[1] <== in[i];
		lt[3][i] = LessEqThan(8);
		lt[3][i].in[0] <== in[i];
		lt[3][i].in[1] <== 122;
		and[1][i] = AND();
		and[1][i].a <== lt[2][i].out;
		and[1][i].b <== lt[3][i].out;
		eq[0][i] = IsEqual();
		eq[0][i].in[0] <== in[i];
		eq[0][i].in[1] <== 45;
		eq[1][i] = IsEqual();
		eq[1][i].in[0] <== in[i];
		eq[1][i].in[1] <== 46;
		eq[2][i] = IsEqual();
		eq[2][i].in[0] <== in[i];
		eq[2][i].in[1] <== 48;
		eq[3][i] = IsEqual();
		eq[3][i].in[0] <== in[i];
		eq[3][i].in[1] <== 49;
		eq[4][i] = IsEqual();
		eq[4][i].in[0] <== in[i];
		eq[4][i].in[1] <== 50;
		eq[5][i] = IsEqual();
		eq[5][i].in[0] <== in[i];
		eq[5][i].in[1] <== 51;
		eq[6][i] = IsEqual();
		eq[6][i].in[0] <== in[i];
		eq[6][i].in[1] <== 52;
		eq[7][i] = IsEqual();
		eq[7][i].in[0] <== in[i];
		eq[7][i].in[1] <== 53;
		eq[8][i] = IsEqual();
		eq[8][i].in[0] <== in[i];
		eq[8][i].in[1] <== 54;
		eq[9][i] = IsEqual();
		eq[9][i].in[0] <== in[i];
		eq[9][i].in[1] <== 55;
		eq[10][i] = IsEqual();
		eq[10][i].in[0] <== in[i];
		eq[10][i].in[1] <== 56;
		eq[11][i] = IsEqual();
		eq[11][i].in[0] <== in[i];
		eq[11][i].in[1] <== 57;
		eq[12][i] = IsEqual();
		eq[12][i].in[0] <== in[i];
		eq[12][i].in[1] <== 95;
		and[2][i] = AND();
		and[2][i].a <== states[i][0];
		multi_or[0][i] = MultiOR(15);
		multi_or[0][i].in[0] <== and[0][i].out;
		multi_or[0][i].in[1] <== and[1][i].out;
		multi_or[0][i].in[2] <== eq[0][i].out;
		multi_or[0][i].in[3] <== eq[1][i].out;
		multi_or[0][i].in[4] <== eq[2][i].out;
		multi_or[0][i].in[5] <== eq[3][i].out;
		multi_or[0][i].in[6] <== eq[4][i].out;
		multi_or[0][i].in[7] <== eq[5][i].out;
		multi_or[0][i].in[8] <== eq[6][i].out;
		multi_or[0][i].in[9] <== eq[7][i].out;
		multi_or[0][i].in[10] <== eq[8][i].out;
		multi_or[0][i].in[11] <== eq[9][i].out;
		multi_or[0][i].in[12] <== eq[10][i].out;
		multi_or[0][i].in[13] <== eq[11][i].out;
		multi_or[0][i].in[14] <== eq[12][i].out;
		and[2][i].b <== multi_or[0][i].out;
		and[3][i] = AND();
		and[3][i].a <== states[i][1];
		and[3][i].b <== multi_or[0][i].out;
		states_tmp[i+1][1] <== and[3][i].out;
		eq[13][i] = IsEqual();
		eq[13][i].in[0] <== in[i];
		eq[13][i].in[1] <== 38;
		and[4][i] = AND();
		and[4][i].a <== states[i][1];
		and[4][i].b <== eq[13][i].out;
		states[i+1][2] <== and[4][i].out;
		eq[14][i] = IsEqual();
		eq[14][i].in[0] <== in[i];
		eq[14][i].in[1] <== 35;
		and[5][i] = AND();
		and[5][i].a <== states[i][2];
		and[5][i].b <== eq[14][i].out;
		states[i+1][3] <== and[5][i].out;
		and[6][i] = AND();
		and[6][i].a <== states[i][3];
		and[6][i].b <== eq[2][i].out;
		states[i+1][4] <== and[6][i].out;
		and[7][i] = AND();
		and[7][i].a <== states[i][4];
		and[7][i].b <== eq[8][i].out;
		states[i+1][5] <== and[7][i].out;
		and[8][i] = AND();
		and[8][i].a <== states[i][5];
		and[8][i].b <== eq[6][i].out;
		states[i+1][6] <== and[8][i].out;
		eq[15][i] = IsEqual();
		eq[15][i].in[0] <== in[i];
		eq[15][i].in[1] <== 59;
		and[9][i] = AND();
		and[9][i].a <== states[i][6];
		and[9][i].b <== eq[15][i].out;
		states[i+1][7] <== and[9][i].out;
		and[10][i] = AND();
		and[10][i].a <== states[i][7];
		multi_or[1][i] = MultiOR(14);
		multi_or[1][i].in[0] <== and[0][i].out;
		multi_or[1][i].in[1] <== and[1][i].out;
		multi_or[1][i].in[2] <== eq[0][i].out;
		multi_or[1][i].in[3] <== eq[1][i].out;
		multi_or[1][i].in[4] <== eq[2][i].out;
		multi_or[1][i].in[5] <== eq[3][i].out;
		multi_or[1][i].in[6] <== eq[4][i].out;
		multi_or[1][i].in[7] <== eq[5][i].out;
		multi_or[1][i].in[8] <== eq[6][i].out;
		multi_or[1][i].in[9] <== eq[7][i].out;
		multi_or[1][i].in[10] <== eq[8][i].out;
		multi_or[1][i].in[11] <== eq[9][i].out;
		multi_or[1][i].in[12] <== eq[10][i].out;
		multi_or[1][i].in[13] <== eq[11][i].out;
		and[10][i].b <== multi_or[1][i].out;
		states[i+1][8] <== and[10][i].out;
		lt[4][i] = LessEqThan(8);
		lt[4][i].in[0] <== 194;
		lt[4][i].in[1] <== in[i];
		lt[5][i] = LessEqThan(8);
		lt[5][i].in[0] <== in[i];
		lt[5][i].in[1] <== 223;
		and[11][i] = AND();
		and[11][i].a <== lt[4][i].out;
		and[11][i].b <== lt[5][i].out;
		and[12][i] = AND();
		and[12][i].a <== states[i][8];
		and[12][i].b <== and[11][i].out;
		lt[6][i] = LessEqThan(8);
		lt[6][i].in[0] <== 160;
		lt[6][i].in[1] <== in[i];
		lt[7][i] = LessEqThan(8);
		lt[7][i].in[0] <== in[i];
		lt[7][i].in[1] <== 191;
		and[13][i] = AND();
		and[13][i].a <== lt[6][i].out;
		and[13][i].b <== lt[7][i].out;
		and[14][i] = AND();
		and[14][i].a <== states[i][10];
		and[14][i].b <== and[13][i].out;
		lt[8][i] = LessEqThan(8);
		lt[8][i].in[0] <== 128;
		lt[8][i].in[1] <== in[i];
		lt[9][i] = LessEqThan(8);
		lt[9][i].in[0] <== in[i];
		lt[9][i].in[1] <== 191;
		and[15][i] = AND();
		and[15][i].a <== lt[8][i].out;
		and[15][i].b <== lt[9][i].out;
		and[16][i] = AND();
		and[16][i].a <== states[i][11];
		and[16][i].b <== and[15][i].out;
		lt[10][i] = LessEqThan(8);
		lt[10][i].in[0] <== 128;
		lt[10][i].in[1] <== in[i];
		lt[11][i] = LessEqThan(8);
		lt[11][i].in[0] <== in[i];
		lt[11][i].in[1] <== 159;
		and[17][i] = AND();
		and[17][i].a <== lt[10][i].out;
		and[17][i].b <== lt[11][i].out;
		and[18][i] = AND();
		and[18][i].a <== states[i][12];
		and[18][i].b <== and[17][i].out;
		and[19][i] = AND();
		and[19][i].a <== states[i][16];
		and[19][i].b <== and[11][i].out;
		and[20][i] = AND();
		and[20][i].a <== states[i][17];
		and[20][i].b <== and[11][i].out;
		and[21][i] = AND();
		and[21][i].a <== states[i][18];
		and[21][i].b <== and[11][i].out;
		and[22][i] = AND();
		and[22][i].a <== states[i][19];
		and[22][i].b <== and[11][i].out;
		and[23][i] = AND();
		and[23][i].a <== states[i][20];
		and[23][i].b <== and[11][i].out;
		and[24][i] = AND();
		and[24][i].a <== states[i][21];
		and[24][i].b <== and[11][i].out;
		and[25][i] = AND();
		and[25][i].a <== states[i][22];
		and[25][i].b <== and[11][i].out;
		multi_or[2][i] = MultiOR(11);
		multi_or[2][i].in[0] <== and[12][i].out;
		multi_or[2][i].in[1] <== and[14][i].out;
		multi_or[2][i].in[2] <== and[16][i].out;
		multi_or[2][i].in[3] <== and[18][i].out;
		multi_or[2][i].in[4] <== and[19][i].out;
		multi_or[2][i].in[5] <== and[20][i].out;
		multi_or[2][i].in[6] <== and[21][i].out;
		multi_or[2][i].in[7] <== and[22][i].out;
		multi_or[2][i].in[8] <== and[23][i].out;
		multi_or[2][i].in[9] <== and[24][i].out;
		multi_or[2][i].in[10] <== and[25][i].out;
		states[i+1][9] <== multi_or[2][i].out;
		eq[16][i] = IsEqual();
		eq[16][i].in[0] <== in[i];
		eq[16][i].in[1] <== 224;
		and[26][i] = AND();
		and[26][i].a <== states[i][8];
		and[26][i].b <== eq[16][i].out;
		and[27][i] = AND();
		and[27][i].a <== states[i][16];
		and[27][i].b <== eq[16][i].out;
		and[28][i] = AND();
		and[28][i].a <== states[i][17];
		and[28][i].b <== eq[16][i].out;
		and[29][i] = AND();
		and[29][i].a <== states[i][18];
		and[29][i].b <== eq[16][i].out;
		and[30][i] = AND();
		and[30][i].a <== states[i][19];
		and[30][i].b <== eq[16][i].out;
		and[31][i] = AND();
		and[31][i].a <== states[i][20];
		and[31][i].b <== eq[16][i].out;
		and[32][i] = AND();
		and[32][i].a <== states[i][21];
		and[32][i].b <== eq[16][i].out;
		and[33][i] = AND();
		and[33][i].a <== states[i][22];
		and[33][i].b <== eq[16][i].out;
		multi_or[3][i] = MultiOR(8);
		multi_or[3][i].in[0] <== and[26][i].out;
		multi_or[3][i].in[1] <== and[27][i].out;
		multi_or[3][i].in[2] <== and[28][i].out;
		multi_or[3][i].in[3] <== and[29][i].out;
		multi_or[3][i].in[4] <== and[30][i].out;
		multi_or[3][i].in[5] <== and[31][i].out;
		multi_or[3][i].in[6] <== and[32][i].out;
		multi_or[3][i].in[7] <== and[33][i].out;
		states[i+1][10] <== multi_or[3][i].out;
		eq[17][i] = IsEqual();
		eq[17][i].in[0] <== in[i];
		eq[17][i].in[1] <== 225;
		eq[18][i] = IsEqual();
		eq[18][i].in[0] <== in[i];
		eq[18][i].in[1] <== 226;
		eq[19][i] = IsEqual();
		eq[19][i].in[0] <== in[i];
		eq[19][i].in[1] <== 227;
		eq[20][i] = IsEqual();
		eq[20][i].in[0] <== in[i];
		eq[20][i].in[1] <== 228;
		eq[21][i] = IsEqual();
		eq[21][i].in[0] <== in[i];
		eq[21][i].in[1] <== 229;
		eq[22][i] = IsEqual();
		eq[22][i].in[0] <== in[i];
		eq[22][i].in[1] <== 230;
		eq[23][i] = IsEqual();
		eq[23][i].in[0] <== in[i];
		eq[23][i].in[1] <== 231;
		eq[24][i] = IsEqual();
		eq[24][i].in[0] <== in[i];
		eq[24][i].in[1] <== 232;
		eq[25][i] = IsEqual();
		eq[25][i].in[0] <== in[i];
		eq[25][i].in[1] <== 233;
		eq[26][i] = IsEqual();
		eq[26][i].in[0] <== in[i];
		eq[26][i].in[1] <== 234;
		eq[27][i] = IsEqual();
		eq[27][i].in[0] <== in[i];
		eq[27][i].in[1] <== 235;
		eq[28][i] = IsEqual();
		eq[28][i].in[0] <== in[i];
		eq[28][i].in[1] <== 236;
		eq[29][i] = IsEqual();
		eq[29][i].in[0] <== in[i];
		eq[29][i].in[1] <== 238;
		eq[30][i] = IsEqual();
		eq[30][i].in[0] <== in[i];
		eq[30][i].in[1] <== 239;
		and[34][i] = AND();
		and[34][i].a <== states[i][8];
		multi_or[4][i] = MultiOR(14);
		multi_or[4][i].in[0] <== eq[17][i].out;
		multi_or[4][i].in[1] <== eq[18][i].out;
		multi_or[4][i].in[2] <== eq[19][i].out;
		multi_or[4][i].in[3] <== eq[20][i].out;
		multi_or[4][i].in[4] <== eq[21][i].out;
		multi_or[4][i].in[5] <== eq[22][i].out;
		multi_or[4][i].in[6] <== eq[23][i].out;
		multi_or[4][i].in[7] <== eq[24][i].out;
		multi_or[4][i].in[8] <== eq[25][i].out;
		multi_or[4][i].in[9] <== eq[26][i].out;
		multi_or[4][i].in[10] <== eq[27][i].out;
		multi_or[4][i].in[11] <== eq[28][i].out;
		multi_or[4][i].in[12] <== eq[29][i].out;
		multi_or[4][i].in[13] <== eq[30][i].out;
		and[34][i].b <== multi_or[4][i].out;
		lt[12][i] = LessEqThan(8);
		lt[12][i].in[0] <== 144;
		lt[12][i].in[1] <== in[i];
		lt[13][i] = LessEqThan(8);
		lt[13][i].in[0] <== in[i];
		lt[13][i].in[1] <== 191;
		and[35][i] = AND();
		and[35][i].a <== lt[12][i].out;
		and[35][i].b <== lt[13][i].out;
		and[36][i] = AND();
		and[36][i].a <== states[i][13];
		and[36][i].b <== and[35][i].out;
		and[37][i] = AND();
		and[37][i].a <== states[i][14];
		and[37][i].b <== and[15][i].out;
		eq[31][i] = IsEqual();
		eq[31][i].in[0] <== in[i];
		eq[31][i].in[1] <== 128;
		eq[32][i] = IsEqual();
		eq[32][i].in[0] <== in[i];
		eq[32][i].in[1] <== 129;
		eq[33][i] = IsEqual();
		eq[33][i].in[0] <== in[i];
		eq[33][i].in[1] <== 130;
		eq[34][i] = IsEqual();
		eq[34][i].in[0] <== in[i];
		eq[34][i].in[1] <== 131;
		eq[35][i] = IsEqual();
		eq[35][i].in[0] <== in[i];
		eq[35][i].in[1] <== 132;
		eq[36][i] = IsEqual();
		eq[36][i].in[0] <== in[i];
		eq[36][i].in[1] <== 133;
		eq[37][i] = IsEqual();
		eq[37][i].in[0] <== in[i];
		eq[37][i].in[1] <== 134;
		eq[38][i] = IsEqual();
		eq[38][i].in[0] <== in[i];
		eq[38][i].in[1] <== 135;
		eq[39][i] = IsEqual();
		eq[39][i].in[0] <== in[i];
		eq[39][i].in[1] <== 136;
		eq[40][i] = IsEqual();
		eq[40][i].in[0] <== in[i];
		eq[40][i].in[1] <== 137;
		eq[41][i] = IsEqual();
		eq[41][i].in[0] <== in[i];
		eq[41][i].in[1] <== 138;
		eq[42][i] = IsEqual();
		eq[42][i].in[0] <== in[i];
		eq[42][i].in[1] <== 139;
		eq[43][i] = IsEqual();
		eq[43][i].in[0] <== in[i];
		eq[43][i].in[1] <== 140;
		eq[44][i] = IsEqual();
		eq[44][i].in[0] <== in[i];
		eq[44][i].in[1] <== 141;
		eq[45][i] = IsEqual();
		eq[45][i].in[0] <== in[i];
		eq[45][i].in[1] <== 142;
		eq[46][i] = IsEqual();
		eq[46][i].in[0] <== in[i];
		eq[46][i].in[1] <== 143;
		and[38][i] = AND();
		and[38][i].a <== states[i][15];
		multi_or[5][i] = MultiOR(16);
		multi_or[5][i].in[0] <== eq[31][i].out;
		multi_or[5][i].in[1] <== eq[32][i].out;
		multi_or[5][i].in[2] <== eq[33][i].out;
		multi_or[5][i].in[3] <== eq[34][i].out;
		multi_or[5][i].in[4] <== eq[35][i].out;
		multi_or[5][i].in[5] <== eq[36][i].out;
		multi_or[5][i].in[6] <== eq[37][i].out;
		multi_or[5][i].in[7] <== eq[38][i].out;
		multi_or[5][i].in[8] <== eq[39][i].out;
		multi_or[5][i].in[9] <== eq[40][i].out;
		multi_or[5][i].in[10] <== eq[41][i].out;
		multi_or[5][i].in[11] <== eq[42][i].out;
		multi_or[5][i].in[12] <== eq[43][i].out;
		multi_or[5][i].in[13] <== eq[44][i].out;
		multi_or[5][i].in[14] <== eq[45][i].out;
		multi_or[5][i].in[15] <== eq[46][i].out;
		and[38][i].b <== multi_or[5][i].out;
		and[39][i] = AND();
		and[39][i].a <== states[i][16];
		and[39][i].b <== multi_or[4][i].out;
		and[40][i] = AND();
		and[40][i].a <== states[i][17];
		and[40][i].b <== multi_or[4][i].out;
		and[41][i] = AND();
		and[41][i].a <== states[i][18];
		and[41][i].b <== multi_or[4][i].out;
		and[42][i] = AND();
		and[42][i].a <== states[i][19];
		and[42][i].b <== multi_or[4][i].out;
		and[43][i] = AND();
		and[43][i].a <== states[i][20];
		and[43][i].b <== multi_or[4][i].out;
		and[44][i] = AND();
		and[44][i].a <== states[i][21];
		and[44][i].b <== multi_or[4][i].out;
		and[45][i] = AND();
		and[45][i].a <== states[i][22];
		and[45][i].b <== multi_or[4][i].out;
		multi_or[6][i] = MultiOR(11);
		multi_or[6][i].in[0] <== and[34][i].out;
		multi_or[6][i].in[1] <== and[36][i].out;
		multi_or[6][i].in[2] <== and[37][i].out;
		multi_or[6][i].in[3] <== and[38][i].out;
		multi_or[6][i].in[4] <== and[39][i].out;
		multi_or[6][i].in[5] <== and[40][i].out;
		multi_or[6][i].in[6] <== and[41][i].out;
		multi_or[6][i].in[7] <== and[42][i].out;
		multi_or[6][i].in[8] <== and[43][i].out;
		multi_or[6][i].in[9] <== and[44][i].out;
		multi_or[6][i].in[10] <== and[45][i].out;
		states[i+1][11] <== multi_or[6][i].out;
		eq[47][i] = IsEqual();
		eq[47][i].in[0] <== in[i];
		eq[47][i].in[1] <== 237;
		and[46][i] = AND();
		and[46][i].a <== states[i][8];
		and[46][i].b <== eq[47][i].out;
		and[47][i] = AND();
		and[47][i].a <== states[i][16];
		and[47][i].b <== eq[47][i].out;
		and[48][i] = AND();
		and[48][i].a <== states[i][17];
		and[48][i].b <== eq[47][i].out;
		and[49][i] = AND();
		and[49][i].a <== states[i][18];
		and[49][i].b <== eq[47][i].out;
		and[50][i] = AND();
		and[50][i].a <== states[i][19];
		and[50][i].b <== eq[47][i].out;
		and[51][i] = AND();
		and[51][i].a <== states[i][20];
		and[51][i].b <== eq[47][i].out;
		and[52][i] = AND();
		and[52][i].a <== states[i][21];
		and[52][i].b <== eq[47][i].out;
		and[53][i] = AND();
		and[53][i].a <== states[i][22];
		and[53][i].b <== eq[47][i].out;
		multi_or[7][i] = MultiOR(8);
		multi_or[7][i].in[0] <== and[46][i].out;
		multi_or[7][i].in[1] <== and[47][i].out;
		multi_or[7][i].in[2] <== and[48][i].out;
		multi_or[7][i].in[3] <== and[49][i].out;
		multi_or[7][i].in[4] <== and[50][i].out;
		multi_or[7][i].in[5] <== and[51][i].out;
		multi_or[7][i].in[6] <== and[52][i].out;
		multi_or[7][i].in[7] <== and[53][i].out;
		states[i+1][12] <== multi_or[7][i].out;
		eq[48][i] = IsEqual();
		eq[48][i].in[0] <== in[i];
		eq[48][i].in[1] <== 240;
		and[54][i] = AND();
		and[54][i].a <== states[i][8];
		and[54][i].b <== eq[48][i].out;
		and[55][i] = AND();
		and[55][i].a <== states[i][16];
		and[55][i].b <== eq[48][i].out;
		and[56][i] = AND();
		and[56][i].a <== states[i][17];
		and[56][i].b <== eq[48][i].out;
		and[57][i] = AND();
		and[57][i].a <== states[i][18];
		and[57][i].b <== eq[48][i].out;
		and[58][i] = AND();
		and[58][i].a <== states[i][19];
		and[58][i].b <== eq[48][i].out;
		and[59][i] = AND();
		and[59][i].a <== states[i][20];
		and[59][i].b <== eq[48][i].out;
		and[60][i] = AND();
		and[60][i].a <== states[i][21];
		and[60][i].b <== eq[48][i].out;
		and[61][i] = AND();
		and[61][i].a <== states[i][22];
		and[61][i].b <== eq[48][i].out;
		multi_or[8][i] = MultiOR(8);
		multi_or[8][i].in[0] <== and[54][i].out;
		multi_or[8][i].in[1] <== and[55][i].out;
		multi_or[8][i].in[2] <== and[56][i].out;
		multi_or[8][i].in[3] <== and[57][i].out;
		multi_or[8][i].in[4] <== and[58][i].out;
		multi_or[8][i].in[5] <== and[59][i].out;
		multi_or[8][i].in[6] <== and[60][i].out;
		multi_or[8][i].in[7] <== and[61][i].out;
		states[i+1][13] <== multi_or[8][i].out;
		eq[49][i] = IsEqual();
		eq[49][i].in[0] <== in[i];
		eq[49][i].in[1] <== 241;
		eq[50][i] = IsEqual();
		eq[50][i].in[0] <== in[i];
		eq[50][i].in[1] <== 242;
		eq[51][i] = IsEqual();
		eq[51][i].in[0] <== in[i];
		eq[51][i].in[1] <== 243;
		and[62][i] = AND();
		and[62][i].a <== states[i][8];
		multi_or[9][i] = MultiOR(3);
		multi_or[9][i].in[0] <== eq[49][i].out;
		multi_or[9][i].in[1] <== eq[50][i].out;
		multi_or[9][i].in[2] <== eq[51][i].out;
		and[62][i].b <== multi_or[9][i].out;
		and[63][i] = AND();
		and[63][i].a <== states[i][16];
		and[63][i].b <== multi_or[9][i].out;
		and[64][i] = AND();
		and[64][i].a <== states[i][17];
		and[64][i].b <== multi_or[9][i].out;
		and[65][i] = AND();
		and[65][i].a <== states[i][18];
		and[65][i].b <== multi_or[9][i].out;
		and[66][i] = AND();
		and[66][i].a <== states[i][19];
		and[66][i].b <== multi_or[9][i].out;
		and[67][i] = AND();
		and[67][i].a <== states[i][20];
		and[67][i].b <== multi_or[9][i].out;
		and[68][i] = AND();
		and[68][i].a <== states[i][21];
		and[68][i].b <== multi_or[9][i].out;
		and[69][i] = AND();
		and[69][i].a <== states[i][22];
		and[69][i].b <== multi_or[9][i].out;
		multi_or[10][i] = MultiOR(8);
		multi_or[10][i].in[0] <== and[62][i].out;
		multi_or[10][i].in[1] <== and[63][i].out;
		multi_or[10][i].in[2] <== and[64][i].out;
		multi_or[10][i].in[3] <== and[65][i].out;
		multi_or[10][i].in[4] <== and[66][i].out;
		multi_or[10][i].in[5] <== and[67][i].out;
		multi_or[10][i].in[6] <== and[68][i].out;
		multi_or[10][i].in[7] <== and[69][i].out;
		states[i+1][14] <== multi_or[10][i].out;
		eq[52][i] = IsEqual();
		eq[52][i].in[0] <== in[i];
		eq[52][i].in[1] <== 244;
		and[70][i] = AND();
		and[70][i].a <== states[i][8];
		and[70][i].b <== eq[52][i].out;
		and[71][i] = AND();
		and[71][i].a <== states[i][16];
		and[71][i].b <== eq[52][i].out;
		and[72][i] = AND();
		and[72][i].a <== states[i][17];
		and[72][i].b <== eq[52][i].out;
		and[73][i] = AND();
		and[73][i].a <== states[i][18];
		and[73][i].b <== eq[52][i].out;
		and[74][i] = AND();
		and[74][i].a <== states[i][19];
		and[74][i].b <== eq[52][i].out;
		and[75][i] = AND();
		and[75][i].a <== states[i][20];
		and[75][i].b <== eq[52][i].out;
		and[76][i] = AND();
		and[76][i].a <== states[i][21];
		and[76][i].b <== eq[52][i].out;
		and[77][i] = AND();
		and[77][i].a <== states[i][22];
		and[77][i].b <== eq[52][i].out;
		multi_or[11][i] = MultiOR(8);
		multi_or[11][i].in[0] <== and[70][i].out;
		multi_or[11][i].in[1] <== and[71][i].out;
		multi_or[11][i].in[2] <== and[72][i].out;
		multi_or[11][i].in[3] <== and[73][i].out;
		multi_or[11][i].in[4] <== and[74][i].out;
		multi_or[11][i].in[5] <== and[75][i].out;
		multi_or[11][i].in[6] <== and[76][i].out;
		multi_or[11][i].in[7] <== and[77][i].out;
		states[i+1][15] <== multi_or[11][i].out;
		lt[14][i] = LessEqThan(8);
		lt[14][i].in[0] <== 1;
		lt[14][i].in[1] <== in[i];
		lt[15][i] = LessEqThan(8);
		lt[15][i].in[0] <== in[i];
		lt[15][i].in[1] <== 127;
		and[78][i] = AND();
		and[78][i].a <== lt[14][i].out;
		and[78][i].b <== lt[15][i].out;
		and[79][i] = AND();
		and[79][i].a <== states[i][8];
		and[79][i].b <== and[78][i].out;
		and[80][i] = AND();
		and[80][i].a <== states[i][9];
		and[80][i].b <== and[15][i].out;
		lt[16][i] = LessEqThan(8);
		lt[16][i].in[0] <== 1;
		lt[16][i].in[1] <== in[i];
		lt[17][i] = LessEqThan(8);
		lt[17][i].in[0] <== in[i];
		lt[17][i].in[1] <== 101;
		and[81][i] = AND();
		and[81][i].a <== lt[16][i].out;
		and[81][i].b <== lt[17][i].out;
		lt[18][i] = LessEqThan(8);
		lt[18][i].in[0] <== 103;
		lt[18][i].in[1] <== in[i];
		lt[19][i] = LessEqThan(8);
		lt[19][i].in[0] <== in[i];
		lt[19][i].in[1] <== 127;
		and[82][i] = AND();
		and[82][i].a <== lt[18][i].out;
		and[82][i].b <== lt[19][i].out;
		and[83][i] = AND();
		and[83][i].a <== states[i][16];
		multi_or[12][i] = MultiOR(2);
		multi_or[12][i].in[0] <== and[81][i].out;
		multi_or[12][i].in[1] <== and[82][i].out;
		and[83][i].b <== multi_or[12][i].out;
		eq[53][i] = IsEqual();
		eq[53][i].in[0] <== in[i];
		eq[53][i].in[1] <== 103;
		eq[54][i] = IsEqual();
		eq[54][i].in[0] <== in[i];
		eq[54][i].in[1] <== 104;
		eq[55][i] = IsEqual();
		eq[55][i].in[0] <== in[i];
		eq[55][i].in[1] <== 105;
		eq[56][i] = IsEqual();
		eq[56][i].in[0] <== in[i];
		eq[56][i].in[1] <== 106;
		eq[57][i] = IsEqual();
		eq[57][i].in[0] <== in[i];
		eq[57][i].in[1] <== 107;
		eq[58][i] = IsEqual();
		eq[58][i].in[0] <== in[i];
		eq[58][i].in[1] <== 108;
		eq[59][i] = IsEqual();
		eq[59][i].in[0] <== in[i];
		eq[59][i].in[1] <== 109;
		eq[60][i] = IsEqual();
		eq[60][i].in[0] <== in[i];
		eq[60][i].in[1] <== 110;
		eq[61][i] = IsEqual();
		eq[61][i].in[0] <== in[i];
		eq[61][i].in[1] <== 112;
		eq[62][i] = IsEqual();
		eq[62][i].in[0] <== in[i];
		eq[62][i].in[1] <== 113;
		eq[63][i] = IsEqual();
		eq[63][i].in[0] <== in[i];
		eq[63][i].in[1] <== 114;
		eq[64][i] = IsEqual();
		eq[64][i].in[0] <== in[i];
		eq[64][i].in[1] <== 115;
		eq[65][i] = IsEqual();
		eq[65][i].in[0] <== in[i];
		eq[65][i].in[1] <== 116;
		eq[66][i] = IsEqual();
		eq[66][i].in[0] <== in[i];
		eq[66][i].in[1] <== 117;
		eq[67][i] = IsEqual();
		eq[67][i].in[0] <== in[i];
		eq[67][i].in[1] <== 118;
		eq[68][i] = IsEqual();
		eq[68][i].in[0] <== in[i];
		eq[68][i].in[1] <== 119;
		eq[69][i] = IsEqual();
		eq[69][i].in[0] <== in[i];
		eq[69][i].in[1] <== 120;
		eq[70][i] = IsEqual();
		eq[70][i].in[0] <== in[i];
		eq[70][i].in[1] <== 121;
		eq[71][i] = IsEqual();
		eq[71][i].in[0] <== in[i];
		eq[71][i].in[1] <== 122;
		eq[72][i] = IsEqual();
		eq[72][i].in[0] <== in[i];
		eq[72][i].in[1] <== 123;
		eq[73][i] = IsEqual();
		eq[73][i].in[0] <== in[i];
		eq[73][i].in[1] <== 124;
		eq[74][i] = IsEqual();
		eq[74][i].in[0] <== in[i];
		eq[74][i].in[1] <== 125;
		eq[75][i] = IsEqual();
		eq[75][i].in[0] <== in[i];
		eq[75][i].in[1] <== 126;
		eq[76][i] = IsEqual();
		eq[76][i].in[0] <== in[i];
		eq[76][i].in[1] <== 127;
		and[84][i] = AND();
		and[84][i].a <== states[i][17];
		multi_or[13][i] = MultiOR(25);
		multi_or[13][i].in[0] <== and[81][i].out;
		multi_or[13][i].in[1] <== eq[53][i].out;
		multi_or[13][i].in[2] <== eq[54][i].out;
		multi_or[13][i].in[3] <== eq[55][i].out;
		multi_or[13][i].in[4] <== eq[56][i].out;
		multi_or[13][i].in[5] <== eq[57][i].out;
		multi_or[13][i].in[6] <== eq[58][i].out;
		multi_or[13][i].in[7] <== eq[59][i].out;
		multi_or[13][i].in[8] <== eq[60][i].out;
		multi_or[13][i].in[9] <== eq[61][i].out;
		multi_or[13][i].in[10] <== eq[62][i].out;
		multi_or[13][i].in[11] <== eq[63][i].out;
		multi_or[13][i].in[12] <== eq[64][i].out;
		multi_or[13][i].in[13] <== eq[65][i].out;
		multi_or[13][i].in[14] <== eq[66][i].out;
		multi_or[13][i].in[15] <== eq[67][i].out;
		multi_or[13][i].in[16] <== eq[68][i].out;
		multi_or[13][i].in[17] <== eq[69][i].out;
		multi_or[13][i].in[18] <== eq[70][i].out;
		multi_or[13][i].in[19] <== eq[71][i].out;
		multi_or[13][i].in[20] <== eq[72][i].out;
		multi_or[13][i].in[21] <== eq[73][i].out;
		multi_or[13][i].in[22] <== eq[74][i].out;
		multi_or[13][i].in[23] <== eq[75][i].out;
		multi_or[13][i].in[24] <== eq[76][i].out;
		and[84][i].b <== multi_or[13][i].out;
		eq[77][i] = IsEqual();
		eq[77][i].in[0] <== in[i];
		eq[77][i].in[1] <== 111;
		and[85][i] = AND();
		and[85][i].a <== states[i][18];
		multi_or[14][i] = MultiOR(25);
		multi_or[14][i].in[0] <== and[81][i].out;
		multi_or[14][i].in[1] <== eq[53][i].out;
		multi_or[14][i].in[2] <== eq[54][i].out;
		multi_or[14][i].in[3] <== eq[55][i].out;
		multi_or[14][i].in[4] <== eq[56][i].out;
		multi_or[14][i].in[5] <== eq[57][i].out;
		multi_or[14][i].in[6] <== eq[58][i].out;
		multi_or[14][i].in[7] <== eq[59][i].out;
		multi_or[14][i].in[8] <== eq[60][i].out;
		multi_or[14][i].in[9] <== eq[77][i].out;
		multi_or[14][i].in[10] <== eq[61][i].out;
		multi_or[14][i].in[11] <== eq[62][i].out;
		multi_or[14][i].in[12] <== eq[64][i].out;
		multi_or[14][i].in[13] <== eq[65][i].out;
		multi_or[14][i].in[14] <== eq[66][i].out;
		multi_or[14][i].in[15] <== eq[67][i].out;
		multi_or[14][i].in[16] <== eq[68][i].out;
		multi_or[14][i].in[17] <== eq[69][i].out;
		multi_or[14][i].in[18] <== eq[70][i].out;
		multi_or[14][i].in[19] <== eq[71][i].out;
		multi_or[14][i].in[20] <== eq[72][i].out;
		multi_or[14][i].in[21] <== eq[73][i].out;
		multi_or[14][i].in[22] <== eq[74][i].out;
		multi_or[14][i].in[23] <== eq[75][i].out;
		multi_or[14][i].in[24] <== eq[76][i].out;
		and[85][i].b <== multi_or[14][i].out;
		lt[20][i] = LessEqThan(8);
		lt[20][i].in[0] <== 1;
		lt[20][i].in[1] <== in[i];
		lt[21][i] = LessEqThan(8);
		lt[21][i].in[0] <== in[i];
		lt[21][i].in[1] <== 31;
		and[86][i] = AND();
		and[86][i].a <== lt[20][i].out;
		and[86][i].b <== lt[21][i].out;
		lt[22][i] = LessEqThan(8);
		lt[22][i].in[0] <== 33;
		lt[22][i].in[1] <== in[i];
		lt[23][i] = LessEqThan(8);
		lt[23][i].in[0] <== in[i];
		lt[23][i].in[1] <== 101;
		and[87][i] = AND();
		and[87][i].a <== lt[22][i].out;
		and[87][i].b <== lt[23][i].out;
		and[88][i] = AND();
		and[88][i].a <== states[i][19];
		multi_or[15][i] = MultiOR(3);
		multi_or[15][i].in[0] <== and[86][i].out;
		multi_or[15][i].in[1] <== and[87][i].out;
		multi_or[15][i].in[2] <== and[82][i].out;
		and[88][i].b <== multi_or[15][i].out;
		lt[24][i] = LessEqThan(8);
		lt[24][i].in[0] <== 1;
		lt[24][i].in[1] <== in[i];
		lt[25][i] = LessEqThan(8);
		lt[25][i].in[0] <== in[i];
		lt[25][i].in[1] <== 45;
		and[89][i] = AND();
		and[89][i].a <== lt[24][i].out;
		and[89][i].b <== lt[25][i].out;
		eq[78][i] = IsEqual();
		eq[78][i].in[0] <== in[i];
		eq[78][i].in[1] <== 47;
		eq[79][i] = IsEqual();
		eq[79][i].in[0] <== in[i];
		eq[79][i].in[1] <== 58;
		eq[80][i] = IsEqual();
		eq[80][i].in[0] <== in[i];
		eq[80][i].in[1] <== 60;
		eq[81][i] = IsEqual();
		eq[81][i].in[0] <== in[i];
		eq[81][i].in[1] <== 62;
		eq[82][i] = IsEqual();
		eq[82][i].in[0] <== in[i];
		eq[82][i].in[1] <== 63;
		eq[83][i] = IsEqual();
		eq[83][i].in[0] <== in[i];
		eq[83][i].in[1] <== 64;
		eq[84][i] = IsEqual();
		eq[84][i].in[0] <== in[i];
		eq[84][i].in[1] <== 91;
		eq[85][i] = IsEqual();
		eq[85][i].in[0] <== in[i];
		eq[85][i].in[1] <== 92;
		eq[86][i] = IsEqual();
		eq[86][i].in[0] <== in[i];
		eq[86][i].in[1] <== 93;
		eq[87][i] = IsEqual();
		eq[87][i].in[0] <== in[i];
		eq[87][i].in[1] <== 94;
		eq[88][i] = IsEqual();
		eq[88][i].in[0] <== in[i];
		eq[88][i].in[1] <== 96;
		and[90][i] = AND();
		and[90][i].a <== states[i][20];
		multi_or[16][i] = MultiOR(28);
		multi_or[16][i].in[0] <== and[89][i].out;
		multi_or[16][i].in[1] <== eq[78][i].out;
		multi_or[16][i].in[2] <== eq[2][i].out;
		multi_or[16][i].in[3] <== eq[3][i].out;
		multi_or[16][i].in[4] <== eq[4][i].out;
		multi_or[16][i].in[5] <== eq[5][i].out;
		multi_or[16][i].in[6] <== eq[6][i].out;
		multi_or[16][i].in[7] <== eq[7][i].out;
		multi_or[16][i].in[8] <== eq[8][i].out;
		multi_or[16][i].in[9] <== eq[9][i].out;
		multi_or[16][i].in[10] <== eq[10][i].out;
		multi_or[16][i].in[11] <== eq[11][i].out;
		multi_or[16][i].in[12] <== eq[79][i].out;
		multi_or[16][i].in[13] <== eq[15][i].out;
		multi_or[16][i].in[14] <== eq[80][i].out;
		multi_or[16][i].in[15] <== eq[81][i].out;
		multi_or[16][i].in[16] <== eq[82][i].out;
		multi_or[16][i].in[17] <== eq[83][i].out;
		multi_or[16][i].in[18] <== eq[84][i].out;
		multi_or[16][i].in[19] <== eq[85][i].out;
		multi_or[16][i].in[20] <== eq[86][i].out;
		multi_or[16][i].in[21] <== eq[87][i].out;
		multi_or[16][i].in[22] <== eq[88][i].out;
		multi_or[16][i].in[23] <== eq[72][i].out;
		multi_or[16][i].in[24] <== eq[73][i].out;
		multi_or[16][i].in[25] <== eq[74][i].out;
		multi_or[16][i].in[26] <== eq[75][i].out;
		multi_or[16][i].in[27] <== eq[76][i].out;
		and[90][i].b <== multi_or[16][i].out;
		lt[26][i] = LessEqThan(8);
		lt[26][i].in[0] <== 11;
		lt[26][i].in[1] <== in[i];
		lt[27][i] = LessEqThan(8);
		lt[27][i].in[0] <== in[i];
		lt[27][i].in[1] <== 101;
		and[91][i] = AND();
		and[91][i].a <== lt[26][i].out;
		and[91][i].b <== lt[27][i].out;
		eq[89][i] = IsEqual();
		eq[89][i].in[0] <== in[i];
		eq[89][i].in[1] <== 1;
		eq[90][i] = IsEqual();
		eq[90][i].in[0] <== in[i];
		eq[90][i].in[1] <== 2;
		eq[91][i] = IsEqual();
		eq[91][i].in[0] <== in[i];
		eq[91][i].in[1] <== 3;
		eq[92][i] = IsEqual();
		eq[92][i].in[0] <== in[i];
		eq[92][i].in[1] <== 4;
		eq[93][i] = IsEqual();
		eq[93][i].in[0] <== in[i];
		eq[93][i].in[1] <== 5;
		eq[94][i] = IsEqual();
		eq[94][i].in[0] <== in[i];
		eq[94][i].in[1] <== 6;
		eq[95][i] = IsEqual();
		eq[95][i].in[0] <== in[i];
		eq[95][i].in[1] <== 7;
		eq[96][i] = IsEqual();
		eq[96][i].in[0] <== in[i];
		eq[96][i].in[1] <== 8;
		eq[97][i] = IsEqual();
		eq[97][i].in[0] <== in[i];
		eq[97][i].in[1] <== 9;
		and[92][i] = AND();
		and[92][i].a <== states[i][21];
		multi_or[17][i] = MultiOR(11);
		multi_or[17][i].in[0] <== and[91][i].out;
		multi_or[17][i].in[1] <== and[82][i].out;
		multi_or[17][i].in[2] <== eq[89][i].out;
		multi_or[17][i].in[3] <== eq[90][i].out;
		multi_or[17][i].in[4] <== eq[91][i].out;
		multi_or[17][i].in[5] <== eq[92][i].out;
		multi_or[17][i].in[6] <== eq[93][i].out;
		multi_or[17][i].in[7] <== eq[94][i].out;
		multi_or[17][i].in[8] <== eq[95][i].out;
		multi_or[17][i].in[9] <== eq[96][i].out;
		multi_or[17][i].in[10] <== eq[97][i].out;
		and[92][i].b <== multi_or[17][i].out;
		lt[28][i] = LessEqThan(8);
		lt[28][i].in[0] <== 47;
		lt[28][i].in[1] <== in[i];
		lt[29][i] = LessEqThan(8);
		lt[29][i].in[0] <== in[i];
		lt[29][i].in[1] <== 64;
		and[93][i] = AND();
		and[93][i].a <== lt[28][i].out;
		and[93][i].b <== lt[29][i].out;
		and[94][i] = AND();
		and[94][i].a <== states[i][22];
		multi_or[18][i] = MultiOR(12);
		multi_or[18][i].in[0] <== and[89][i].out;
		multi_or[18][i].in[1] <== and[93][i].out;
		multi_or[18][i].in[2] <== eq[84][i].out;
		multi_or[18][i].in[3] <== eq[85][i].out;
		multi_or[18][i].in[4] <== eq[86][i].out;
		multi_or[18][i].in[5] <== eq[87][i].out;
		multi_or[18][i].in[6] <== eq[88][i].out;
		multi_or[18][i].in[7] <== eq[72][i].out;
		multi_or[18][i].in[8] <== eq[73][i].out;
		multi_or[18][i].in[9] <== eq[74][i].out;
		multi_or[18][i].in[10] <== eq[75][i].out;
		multi_or[18][i].in[11] <== eq[76][i].out;
		and[94][i].b <== multi_or[18][i].out;
		multi_or[19][i] = MultiOR(9);
		multi_or[19][i].in[0] <== and[79][i].out;
		multi_or[19][i].in[1] <== and[80][i].out;
		multi_or[19][i].in[2] <== and[83][i].out;
		multi_or[19][i].in[3] <== and[84][i].out;
		multi_or[19][i].in[4] <== and[85][i].out;
		multi_or[19][i].in[5] <== and[88][i].out;
		multi_or[19][i].in[6] <== and[90][i].out;
		multi_or[19][i].in[7] <== and[92][i].out;
		multi_or[19][i].in[8] <== and[94][i].out;
		states[i+1][16] <== multi_or[19][i].out;
		eq[98][i] = IsEqual();
		eq[98][i].in[0] <== in[i];
		eq[98][i].in[1] <== 102;
		and[95][i] = AND();
		and[95][i].a <== states[i][16];
		and[95][i].b <== eq[98][i].out;
		and[96][i] = AND();
		and[96][i].a <== states[i][17];
		and[96][i].b <== eq[98][i].out;
		and[97][i] = AND();
		and[97][i].a <== states[i][18];
		and[97][i].b <== eq[98][i].out;
		and[98][i] = AND();
		and[98][i].a <== states[i][19];
		and[98][i].b <== eq[98][i].out;
		and[99][i] = AND();
		and[99][i].a <== states[i][21];
		and[99][i].b <== eq[98][i].out;
		multi_or[20][i] = MultiOR(5);
		multi_or[20][i].in[0] <== and[95][i].out;
		multi_or[20][i].in[1] <== and[96][i].out;
		multi_or[20][i].in[2] <== and[97][i].out;
		multi_or[20][i].in[3] <== and[98][i].out;
		multi_or[20][i].in[4] <== and[99][i].out;
		states[i+1][17] <== multi_or[20][i].out;
		and[100][i] = AND();
		and[100][i].a <== states[i][17];
		and[100][i].b <== eq[77][i].out;
		states[i+1][18] <== and[100][i].out;
		and[101][i] = AND();
		and[101][i].a <== states[i][18];
		and[101][i].b <== eq[63][i].out;
		states[i+1][19] <== and[101][i].out;
		eq[99][i] = IsEqual();
		eq[99][i].in[0] <== in[i];
		eq[99][i].in[1] <== 32;
		and[102][i] = AND();
		and[102][i].a <== states[i][19];
		and[102][i].b <== eq[99][i].out;
		states[i+1][20] <== and[102][i].out;
		eq[100][i] = IsEqual();
		eq[100][i].in[0] <== in[i];
		eq[100][i].in[1] <== 61;
		and[103][i] = AND();
		and[103][i].a <== states[i][20];
		and[103][i].b <== eq[100][i].out;
		states[i+1][21] <== and[103][i].out;
		eq[101][i] = IsEqual();
		eq[101][i].in[0] <== in[i];
		eq[101][i].in[1] <== 10;
		and[104][i] = AND();
		and[104][i].a <== states[i][21];
		and[104][i].b <== eq[101][i].out;
		states[i+1][22] <== and[104][i].out;
		and[105][i] = AND();
		and[105][i].a <== states[i][20];
		multi_or[21][i] = MultiOR(4);
		multi_or[21][i].in[0] <== and[0][i].out;
		multi_or[21][i].in[1] <== and[1][i].out;
		multi_or[21][i].in[2] <== eq[1][i].out;
		multi_or[21][i].in[3] <== eq[12][i].out;
		and[105][i].b <== multi_or[21][i].out;
		and[106][i] = AND();
		and[106][i].a <== states[i][22];
		and[106][i].b <== multi_or[21][i].out;
		and[107][i] = AND();
		and[107][i].a <== states[i][23];
		multi_or[22][i] = MultiOR(3);
		multi_or[22][i].in[0] <== and[0][i].out;
		multi_or[22][i].in[1] <== and[1][i].out;
		multi_or[22][i].in[2] <== eq[12][i].out;
		and[107][i].b <== multi_or[22][i].out;
		multi_or[23][i] = MultiOR(3);
		multi_or[23][i].in[0] <== and[105][i].out;
		multi_or[23][i].in[1] <== and[106][i].out;
		multi_or[23][i].in[2] <== and[107][i].out;
		states[i+1][23] <== multi_or[23][i].out;
		and[108][i] = AND();
		and[108][i].a <== states[i][23];
		and[108][i].b <== eq[1][i].out;
		states[i+1][24] <== and[108][i].out;
		from_zero_enabled[i] <== MultiNOR(24)([states_tmp[i+1][1], states[i+1][2], states[i+1][3], states[i+1][4], states[i+1][5], states[i+1][6], states[i+1][7], states[i+1][8], states[i+1][9], states[i+1][10], states[i+1][11], states[i+1][12], states[i+1][13], states[i+1][14], states[i+1][15], states[i+1][16], states[i+1][17], states[i+1][18], states[i+1][19], states[i+1][20], states[i+1][21], states[i+1][22], states[i+1][23], states[i+1][24]]);
		states[i+1][1] <== MultiOR(2)([states_tmp[i+1][1], from_zero_enabled[i] * and[2][i].out]);
		state_changed[i].in[0] <== states[i+1][1];
		state_changed[i].in[1] <== states[i+1][2];
		state_changed[i].in[2] <== states[i+1][3];
		state_changed[i].in[3] <== states[i+1][4];
		state_changed[i].in[4] <== states[i+1][5];
		state_changed[i].in[5] <== states[i+1][6];
		state_changed[i].in[6] <== states[i+1][7];
		state_changed[i].in[7] <== states[i+1][8];
		state_changed[i].in[8] <== states[i+1][9];
		state_changed[i].in[9] <== states[i+1][10];
		state_changed[i].in[10] <== states[i+1][11];
		state_changed[i].in[11] <== states[i+1][12];
		state_changed[i].in[12] <== states[i+1][13];
		state_changed[i].in[13] <== states[i+1][14];
		state_changed[i].in[14] <== states[i+1][15];
		state_changed[i].in[15] <== states[i+1][16];
		state_changed[i].in[16] <== states[i+1][17];
		state_changed[i].in[17] <== states[i+1][18];
		state_changed[i].in[18] <== states[i+1][19];
		state_changed[i].in[19] <== states[i+1][20];
		state_changed[i].in[20] <== states[i+1][21];
		state_changed[i].in[21] <== states[i+1][22];
		state_changed[i].in[22] <== states[i+1][23];
		state_changed[i].in[23] <== states[i+1][24];
	}

	component is_accepted = MultiOR(num_bytes+1);
	for (var i = 0; i <= num_bytes; i++) {
		is_accepted.in[i] <== states[i][24];
	}
	out <== is_accepted.out;
	signal is_consecutive[msg_bytes+1][3];
	is_consecutive[msg_bytes][2] <== 0;
	for (var i = 0; i < msg_bytes; i++) {
		is_consecutive[msg_bytes-1-i][0] <== states[num_bytes-i][24] * (1 - is_consecutive[msg_bytes-i][2]) + is_consecutive[msg_bytes-i][2];
		is_consecutive[msg_bytes-1-i][1] <== state_changed[msg_bytes-i].out * is_consecutive[msg_bytes-1-i][0];
		is_consecutive[msg_bytes-1-i][2] <== ORAnd()([(1 - from_zero_enabled[msg_bytes-i+1]), states[num_bytes-i][24], is_consecutive[msg_bytes-1-i][1]]);
	}
	// substrings calculated: [{(0, 1), (1, 1), (1, 2), (2, 3), (3, 4), (4, 5), (5, 6), (6, 7), (7, 8), (8, 8)}, {(20, 23), (22, 23), (23, 23)}]
	signal prev_states0[10][msg_bytes];
	signal is_substr0[msg_bytes];
	signal is_reveal0[msg_bytes];
	signal output reveal0[msg_bytes];
	for (var i = 0; i < msg_bytes; i++) {
		 // the 0-th substring transitions: [(0, 1), (1, 1), (1, 2), (2, 3), (3, 4), (4, 5), (5, 6), (6, 7), (7, 8), (8, 8)]
		prev_states0[0][i] <== from_zero_enabled[i+1] * states[i+1][0];
		prev_states0[1][i] <== (1 - from_zero_enabled[i+1]) * states[i+1][1];
		prev_states0[2][i] <== (1 - from_zero_enabled[i+1]) * states[i+1][1];
		prev_states0[3][i] <== (1 - from_zero_enabled[i+1]) * states[i+1][2];
		prev_states0[4][i] <== (1 - from_zero_enabled[i+1]) * states[i+1][3];
		prev_states0[5][i] <== (1 - from_zero_enabled[i+1]) * states[i+1][4];
		prev_states0[6][i] <== (1 - from_zero_enabled[i+1]) * states[i+1][5];
		prev_states0[7][i] <== (1 - from_zero_enabled[i+1]) * states[i+1][6];
		prev_states0[8][i] <== (1 - from_zero_enabled[i+1]) * states[i+1][7];
		prev_states0[9][i] <== (1 - from_zero_enabled[i+1]) * states[i+1][8];
		is_substr0[i] <== MultiOR(10)([prev_states0[0][i] * states[i+2][1], prev_states0[1][i] * states[i+2][1], prev_states0[2][i] * states[i+2][2], prev_states0[3][i] * states[i+2][3], prev_states0[4][i] * states[i+2][4], prev_states0[5][i] * states[i+2][5], prev_states0[6][i] * states[i+2][6], prev_states0[7][i] * states[i+2][7], prev_states0[8][i] * states[i+2][8], prev_states0[9][i] * states[i+2][8]]);
		is_reveal0[i] <== MultiAND(3)([out, is_substr0[i], is_consecutive[i][2]]);
		reveal0[i] <== in[i+1] * is_reveal0[i];
	}
	signal prev_states1[3][msg_bytes];
	signal is_substr1[msg_bytes];
	signal is_reveal1[msg_bytes];
	signal output reveal1[msg_bytes];
	for (var i = 0; i < msg_bytes; i++) {
		 // the 1-th substring transitions: [(20, 23), (22, 23), (23, 23)]
		prev_states1[0][i] <== (1 - from_zero_enabled[i+1]) * states[i+1][20];
		prev_states1[1][i] <== (1 - from_zero_enabled[i+1]) * states[i+1][22];
		prev_states1[2][i] <== (1 - from_zero_enabled[i+1]) * states[i+1][23];
		is_substr1[i] <== MultiOR(3)([prev_states1[0][i] * states[i+2][23], prev_states1[1][i] * states[i+2][23], prev_states1[2][i] * states[i+2][23]]);
		is_reveal1[i] <== MultiAND(3)([out, is_substr1[i], is_consecutive[i][2]]);
		reveal1[i] <== in[i+1] * is_reveal1[i];
	}
}