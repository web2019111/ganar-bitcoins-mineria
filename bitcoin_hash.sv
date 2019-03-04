module bitcoin_hash (input logic clk, reset_n, start,
                     input logic [31:0] message_addr, output_addr,
                    output logic done, mem_clk, mem_we,
                    output logic [15:0] mem_addr,
                    output logic [31:0] mem_write_data,
                     input logic [31:0] mem_read_data);

parameter NUM_NONCES = 16;

parameter pad = 32'h80000000;
parameter zero = 32'h00000000;
parameter size1 = 32'h00000280;
parameter size2 = 32'h00000100;

int          words_count;
int          output_count;
logic			 first_hash;
logic        second_hash;

logic [31:0] H0[NUM_NONCES];
logic [31:0] H1[NUM_NONCES];
logic [31:0] H2[NUM_NONCES];
logic [31:0] H3[NUM_NONCES];
logic [31:0] H4[NUM_NONCES];
logic [31:0] H5[NUM_NONCES];
logic [31:0] H6[NUM_NONCES];
logic [31:0] H7[NUM_NONCES];

logic [31:0] A[NUM_NONCES], B[NUM_NONCES], C[NUM_NONCES], D[NUM_NONCES];
logic [31:0] E[NUM_NONCES], F[NUM_NONCES], G[NUM_NONCES], H[NUM_NONCES];
logic [31:0] p[NUM_NONCES];

logic [ 7:0] t;

logic [31:0] w[NUM_NONCES][16];

parameter int K[0:62] = '{
   32'h71374491, 32'hb5c0fbcf, 32'he9b5dba5, 32'h3956c25b, 32'h59f111f1, 32'h923f82a4, 32'hab1c5ed5,
   32'hd807aa98, 32'h12835b01, 32'h243185be, 32'h550c7dc3, 32'h72be5d74, 32'h80deb1fe, 32'h9bdc06a7, 32'hc19bf174,
   32'he49b69c1, 32'hefbe4786, 32'h0fc19dc6, 32'h240ca1cc, 32'h2de92c6f, 32'h4a7484aa, 32'h5cb0a9dc, 32'h76f988da,
   32'h983e5152, 32'ha831c66d, 32'hb00327c8, 32'hbf597fc7, 32'hc6e00bf3, 32'hd5a79147, 32'h06ca6351, 32'h14292967,
   32'h27b70a85, 32'h2e1b2138, 32'h4d2c6dfc, 32'h53380d13, 32'h650a7354, 32'h766a0abb, 32'h81c2c92e, 32'h92722c85,
   32'ha2bfe8a1, 32'ha81a664b, 32'hc24b8b70, 32'hc76c51a3, 32'hd192e819, 32'hd6990624, 32'hf40e3585, 32'h106aa070,
   32'h19a4c116, 32'h1e376c08, 32'h2748774c, 32'h34b0bcb5, 32'h391c0cb3, 32'h4ed8aa4a, 32'h5b9cca4f, 32'h682e6ff3,
   32'h748f82ee, 32'h78a5636f, 32'h84c87814, 32'h8cc70208, 32'h90befffa, 32'ha4506ceb, 32'hbef9a3f7, 32'hc67178f2
};

function logic [31:0] rrot(input logic [31:0] word, input int bits);
     rrot = ((word>>bits) | (word<<(32-bits)));
endfunction

function logic [31:0] wt_new(input logic [31:0] word[0:15]); 
	  logic [31:0] s0, s1; 
     s0 = rrot(word[1],7)^rrot(word[1],18)^(word[1]>>3);     
	  s1 = rrot(word[14],17)^rrot(word[14],19)^(word[14]>>10);     
	  wt_new = word[0] + s0 + word[9] + s1; 
endfunction

function logic [63:0] sha256_block(input logic [31:0] A, B, C, D, E, F, G, p);
    logic[31:0] t1, t2;

    t1 = ((E & F)|((~E) & G)) + (rrot(E, 6)^rrot(E, 11)^rrot(E, 25)) + p;
    t2 = ((A & B)|(A & C)|(B & C)) + (rrot(A, 2)^rrot(A, 13)^rrot(A, 22));
    sha256_block = {t1 + t2, D + t1};
endfunction

enum logic [2:0] {IDLE, READ, UPDATE, PREP, FIRST_BLOCK, PARA_SEC_BLOCK, DONE} state;

assign mem_clk = clk;

always_ff @(posedge clk, negedge reset_n)
begin
    if (!reset_n)
	 begin
        state <= IDLE;
	 end
    else begin
        case(state)
				IDLE: begin
					if(start)
					begin
						state <= READ;
						mem_we <= 0;
						mem_addr <= message_addr + words_count;
						words_count <= words_count + 1;
						words_count <= 0;
						output_count <= 0;
			  
						first_hash <= 1'b0;
						second_hash <= 1'b0;			  
						done <= 1'b0;
					end
				end
				READ: begin
                    words_count <= words_count + 1;

                    if (words_count < 2)
                        mem_addr <= message_addr + words_count;
                    else if (words_count >= 2 && words_count < 18) begin
                        w[0][words_count - 2] <= mem_read_data; // NOTE: AVOID [words_count - 2] which creates MUX/DEC
                        mem_addr <= message_addr + words_count;
                    end else if (words_count == 18) begin
                        w[1][words_count - 18] <= mem_read_data; // NOTE: AVOID [words_count - 2] which creates MUX/DEC
								mem_addr <= message_addr + words_count;
						  end else if (words_count >=19 && words_count < 21)
								w[1][words_count - 18] <= mem_read_data;
                    else begin
                        state <= UPDATE;
								first_hash <= 1'b1;
								second_hash <= 1'b0;
                        w[0][15] <= w[0][0];
                        for (int i=0; i<15; i++) w[0][i] <= w[0][i+1];
                    end
						end
					 
				UPDATE: begin
					if(first_hash) begin
							  H0[0] <= 32'h6a09e667;
							  H1[0] <= 32'hbb67ae85;
							  H2[0] <= 32'h3c6ef372;
							  H3[0] <= 32'ha54ff53a;
							  H4[0] <= 32'h510e527f;
							  H5[0] <= 32'h9b05688c;
							  H6[0] <= 32'h1f83d9ab;
							  H7[0] <= 32'h5be0cd19;

							  A[0] <= 32'h6a09e667;
							  B[0] <= 32'hbb67ae85;
							  C[0] <= 32'h3c6ef372;
							  D[0] <= 32'ha54ff53a;
							  E[0] <= 32'h510e527f;
							  F[0] <= 32'h9b05688c;
							  G[0] <= 32'h1f83d9ab;
							  H[0] <= 32'h5be0cd19;
							  
							  
							  state <= PREP;
						  end
						  else if(second_hash) begin
								for(int n=0; n<NUM_NONCES; n++) begin
									H0[n] <= H0[0] + A[0];
                           H1[n] <= H1[0] + B[0];
                           H2[n] <= H2[0] + C[0];
                           H3[n] <= H3[0] + D[0];
                           H4[n] <= H4[0] + E[0];
                           H5[n] <= H5[0] + F[0];
                           H6[n] <= H6[0] + G[0];
                           H7[n] <= H7[0] + H[0];
									 
									A[n] <= H0[0] + A[0];
                           B[n] <= H1[0] + B[0];
                           C[n] <= H2[0] + C[0];
                           D[n] <= H3[0] + D[0];
                           E[n] <= H4[0] + E[0];
                           F[n] <= H5[0] + F[0];
                           G[n] <= H6[0] + G[0];
                           H[n] <= H7[0] + H[0];
								end
								state <= PREP;
						  end
						  else begin
								for(int n=0; n< NUM_NONCES; n++) begin			
									A[n] <= 32'h6a09e667;
									B[n] <= 32'hbb67ae85;
									C[n] <= 32'h3c6ef372;
									D[n] <= 32'ha54ff53a;
									E[n] <= 32'h510e527f;
									F[n] <= 32'h9b05688c;
									G[n] <= 32'h1f83d9ab;
									H[n] <= 32'h5be0cd19;
									
									w[n][15] <= H0[n] + A[n];
									w[n][0] <= H1[n] + B[n];
									w[n][1] <= H2[n] + C[n];
									w[n][2] <= H3[n] + D[n];
									w[n][3] <= H4[n] + E[n];
									w[n][4] <= H5[n] + F[n];
									w[n][5] <= H6[n] + G[n];
									w[n][6] <= H7[n] + H[n];
								end
								state <= PREP;
						  end
				end
            PREP:	begin

                    t <= 0;
						  if(first_hash) begin
							  
							  p[0] <= 32'h428a2f98 + 32'h5be0cd19 + w[0][15];
							  w[0][15] <= w[0][0];
							  for(int i=0; i<15; i++) w[0][i] <= w[0][i+1];
							  state <= FIRST_BLOCK;
						  end
						  else if(second_hash) begin
								for(int n=0; n<NUM_NONCES; n++) begin
									
									p[n] <= H[n] + 32'h428a2f98 + w[n][15];
									w[n][15] <= w[0][0];
									for(int i=0; i<15; i++) w[n][i] <= w[n][i+1];
									
								end
								state <= PARA_SEC_BLOCK;
						  end
						  else begin
								for(int n=0; n< NUM_NONCES; n++) begin
								
									p[n] <= 32'h9e6afcb1 + w[n][15];
									w[n][15] <= w[n][0];
									for(int i=0; i<15; i++) w[n][i] <= w[n][i+1];
									 
								end
								state <= PARA_SEC_BLOCK;
						  end
                end

            FIRST_BLOCK: begin
						  {A[0], E[0]} <= sha256_block(A[0], B[0], C[0], D[0], E[0], F[0], G[0], p[0]);
						  B[0] <= A[0];
						  C[0] <= B[0];
						  D[0] <= C[0];
						  F[0] <= E[0];
						  G[0] <= F[0];
						  H[0] <= G[0];
						  
                    p[0] <= K[t] + G[0] + w[0][15]; 

                    if (t < 63) begin
                        t <= t + 1;
                        if (t<14)
                            w[0][15] <= w[0][0];
                        else
                            w[0][15] <=  wt_new(w[0]);
                        for (int j = 0; j < 15; j++) w[0][j] <= w[0][j+1];
                    end else begin
                        state <= UPDATE;
								first_hash <= 1'b0;
								second_hash <= 1'b1;
                        for (int n=0; n<NUM_NONCES; n++) begin
                            w[n][15] <= w[1][0];
                            w[n][0] <= w[1][1];
                            w[n][1] <= w[1][2];
                            w[n][2] <= n;
									 w[n][3] <= pad;

                            for (int m=4; m<14; m++) w[n][m] <= zero;

                            w[n][14] <= size1;
                        end
                    end
                end

            PARA_SEC_BLOCK: begin
                    for (int n=0; n<NUM_NONCES; n++) begin
									 {A[n], E[n]} <= sha256_block(A[n], B[n], C[n], D[n], E[n], F[n], G[n], p[n]);
									 B[n] <= A[n];
									 C[n] <= B[n];
								    D[n] <= C[n];
								    F[n] <= E[n];
									 G[n] <= F[n];
									 H[n] <= G[n];
									 
                            p[n] <= K[t] + G[n] + w[n][15];
                    end
						  
                    if (t<63) begin
								t <= t + 1;
                        for (int n=0; n<NUM_NONCES; n++) begin
                            
                            if (t<14)
                                w[n][15] <= w[n][0];
                            else
                                w[n][15] <=  wt_new(w[n]);
                            for (int j = 0; j < 15; j++) w[n][j] <= w[n][j+1];
                        end
                    end else begin
                        if (second_hash) begin
                            state <= UPDATE;
									 first_hash <= 1'b0;
									 second_hash <= 1'b0;
                            for (int n=0; n<NUM_NONCES; n++) begin
                                w[n][7] <= pad;
                                for (int m=8; m<14; m++) w[n][m] <= zero;
                                w[n][14] <= size2;  
                            end
                        end else
                            state <= DONE;
                    end
                end

            DONE: begin
                    output_count <= output_count + 1;
                    if (output_count < NUM_NONCES) begin
                        mem_we <= 1;
                        mem_write_data <= 32'h6a09e667 + A[output_count];
                        mem_addr <= output_addr + output_count;
                    end else
                        done <= 1'b1;
            end
        endcase
    end
end
endmodule
