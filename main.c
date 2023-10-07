#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h> 
#include <arpa/inet.h>
#include <inttypes.h>

#include "main.h"
#define MAX 512

//min of two integers
int min(int a, int b){
    if(a<b){
        return a;
    }
    return b;
}

//print the field of struct packet
void print_packet(struct dns_r_packet *r_packet){

//print header
    printf("id: %hu, ", r_packet->r_header->id);
    printf("qr: %u, ", r_packet->r_header->qr);
    printf("opcode: %u, ", r_packet->r_header->opcode);
    printf("aa: %u, ", r_packet->r_header->aa);
    printf("tc: %u, ", r_packet->r_header->tc);
    printf("rd: %u, ", r_packet->r_header->rd);
    printf("ra: %u, ", r_packet->r_header->ra);
    printf("z: %u, ", r_packet->r_header->z);
    printf("rcode: %u, ", r_packet->r_header->rcode);
    printf("qdcount: %u, ", r_packet->r_header->qdcount);
    printf("ancount: %u, ", r_packet->r_header->ancount);
    printf("nscount: %u, ", r_packet->r_header->nscount);
    printf("arcount: %u, \n", r_packet->r_header->arcount);

//prints questions
    struct dns_question *q;
    q = r_packet->r_question;
    while(q){
        printf("qname: %s, ", q->qname);
        printf("qtype: %u, ", q->qtype);
        printf("qclass: %u, \n", q->qclass);

        q = q->next;       
    }

//prints answers
    struct dns_answer *r;
    r = r_packet->r_answer;
    while(r){
       printf("name: %s, ", r->name); 
        printf("type: %u, ", r->type);
        printf("class: %u, ", r->class);
        printf("ttl: %u, ", r->ttl);     
        printf("rdlength: %u, ", r->rdlength);
        printf("rdata: ");
        for (int i = 0; i < 4; ++i){
            printf("%s%u", (i ? "." : ""), r->addr[i]);
        }
        printf("\n");

        r = r->next;  
    }
    printf("\n");
}

//get 16 bits from the buff
uint16_t get_16bits(const uint8_t **buff){
    uint16_t val;
    memcpy(&val, *buff, 2);
    (*buff) += 2;
    return ntohs(val);
}

//fills addr field of response record struct
int get_A_record(uint8_t addr[4], const char domain_name[]){
    //printf("domain name is %s\n", domain_name);
    int strcmp_res = strcmp(domain_name, "www.everus.com") ;
    if( strcmp_res  == 0){
        //printf("into if\n");
        addr[0] = 192;
        addr[1] = 168;
        addr[2] = 1;
        addr[3] = 11;
        return 0;
    }
     return -1;
}

//set fields of header struct from the buff
void decode_header(const uint8_t **buff, struct dns_r_packet *r_packet){

    r_packet->r_header = calloc(1, sizeof (struct dns_header));
    r_packet->r_header->id = get_16bits(buff);

    uint32_t flags = get_16bits(buff);
    r_packet->r_header->qr = (flags & QR_MASK ) >> 15;   
    r_packet->r_header->opcode = (flags & OPCODE_MASK) >> 11;
    r_packet->r_header->aa = (flags & AA_MASK) >> 10;
    r_packet->r_header->tc = (flags & TC_MASK ) >> 9;
    r_packet->r_header->rd = (flags & RD_MASK ) >> 8;
    r_packet->r_header->ra = (flags & RA_MASK) >> 7;
    r_packet->r_header->z = (flags & Z_MASK ) >> 4;
    r_packet->r_header->rcode = (flags & RCODE_MASK) >> 0;

    r_packet->r_header->qdcount = get_16bits(buff);
    r_packet->r_header->ancount = get_16bits(buff);
    r_packet->r_header->nscount = get_16bits(buff);
    r_packet->r_header->arcount = get_16bits(buff);
}

//copy the domain name from buff
char *decode_domain_name(uint8_t **buff, int len){

    char msg[MAX];
    memset(&msg, 0, MAX);
    int min_res = min(len, MAX);

    for(int i=1; i< min_res; i++){
        uint8_t c = (*buff)[i];
        if(c == 0){
            msg[i-1]= 0;
            *buff += i+1;
            printf("\n");
            return strdup(msg);
        }
        else if((c >= 'a' && c <= 'z' ) || c == '-'){
            msg[i-1] = c;
        }
        else{
            msg[i-1] = '.';
        }
    }  
    return NULL;
}


//set the fields of struct packet from contents of buff
int decode_packet(const uint8_t *buff, struct dns_r_packet *r_packet, int size){

    //set fields of header struct
    decode_header(&buff, r_packet);

    //check if it is a querry packet
    if(r_packet->r_header->nscount != 0 || r_packet ->r_header->ancount != 0){
        printf("only questions expected\n");
        return -1;
    }

    //set fields of question struct
    struct dns_question *r_question;
    int q_count = r_packet->r_header->qdcount;
    for(int i=0; i<q_count; i++){
        //printf("question count %d is \n", i);
        r_question = calloc(1, sizeof(struct dns_question));
        r_question->qname = decode_domain_name(&buff, size);
        r_question->qtype = get_16bits(&buff);
        r_question->qclass = get_16bits(&buff);

        if(r_question->qname == NULL){
            printf("failed to fecode domain name\n");
            return -1;
        }

        //prepend question to the linked list
        r_question->next = r_packet->r_question;
        r_packet->r_question = r_question;
        //printf("r_question address is %d\n", r_question);

        //for the first question set next as NULL
       if(i== 0){
        r_question->next = NULL; 
       }
    }
    return 0;
}

//modify and prep the fields of packet for response-packet
void resolve_query(struct dns_r_packet *r_packet){

    //printf("r_packet is in resolve query  %d\n", r_packet);
    struct dns_answer *rr;
    struct dns_answer *r;
    struct dns_question *q;
    int get_A_record_res; 

    //modify header
    r_packet->r_header->qr = 1;//its is a response
    r_packet->r_header->aa = 1;//authoritative answer
    r_packet->r_header->rd = 1;//no to recursion
    r_packet->r_header->ra = 1;//no to recursion
    r_packet->r_header->rcode = 0;//no error condition
    r_packet->r_header->nscount  = 0;
    r_packet->r_header->ancount  = 0;
    r_packet->r_header->arcount = 0;
    r_packet->r_header->qdcount = 1;
     
     //for each question create response struct and fill-in
    q = r_packet->r_question;
    //printf("after replace r_question\n");
    while(q){
        r = calloc(1, sizeof (struct dns_answer));
        memset(r, 0, sizeof(struct dns_answer));
        r->name = strdup(q->qname);
        r->type= q->qtype;
        r->class= q->qclass;
        r->ttl = 30*30;

        //printf("Query for '%s'\n", q->qname);
        
        get_A_record_res = get_A_record(r->addr, q->qname);
        if(get_A_record_res<0){
          free(r);
          goto next;
        }
        r->rdlength = 4;
        r_packet->r_header->ancount++; //number of resource records.

        //prepend to the response linked list
        rr = r_packet->r_answer;
        r_packet->r_answer = r;
        r->next = rr;

        //control jumps here to exit
        next:
        q = q->next;
    }   
}

//put uint8_t  value into the buff
void put_8bits(const uint8_t **buff, uint8_t value){
    //no need to convert value to network byte order
    memcpy(*buff, &value, 1);
    *buff += 1;
}

//put uint16_t  value into the buff
void put_16bits(const uint8_t **buff, uint16_t value){
    value = htons(value);
    memcpy(*buff, &value, 2);
    *buff += 2;
}

//put uint32_t  value into the buff
void put_32bits(const uint8_t **buff, uint32_t value){
    value = htonl(value);
    memcpy(*buff, &value, 4);
    *buff += 4;
}

//put contents of the header struct to the buff
void encode_header (uint8_t **buff, struct dns_r_packet *r_packet){

    //put the header struct into the buff
    put_16bits(buff, r_packet->r_header->id);
    int fields =0;
    fields |= (r_packet->r_header->qr << 15) & QR_MASK;
    fields |= (r_packet->r_header->opcode << 11) & OPCODE_MASK;
    fields |= (r_packet->r_header->aa << 10) & AA_MASK;
    fields |= (r_packet->r_header->tc << 9) & TC_MASK;
    fields |= (r_packet->r_header->rd << 8) & RD_MASK ;
    fields |= (r_packet->r_header->ra << 7) & RA_MASK;
    fields |= (r_packet->r_header->z << 4) & Z_MASK;
    fields |= (r_packet->r_header->rcode << 0) & RCODE_MASK;
    put_16bits(buff, fields);

    put_16bits(buff, r_packet->r_header->qdcount);
    put_16bits(buff, r_packet->r_header->ancount); 
    put_16bits(buff, r_packet->r_header->nscount);
    put_16bits(buff, r_packet->r_header->arcount);
}

//put the domain name into buff
int encode_domain_name(const uint8_t **buff, const char *domain){
    const char *domain_in_packet = domain; //point to start of qname
    const char *str_ptr; //to record results of strchr

    uint8_t *buffer = *buff;
    int len; 
    int i=0;//index of buffer
    while(str_ptr = strchr(domain_in_packet ,'.' )){
        len = (str_ptr - domain_in_packet);
        //printf("len in wncode domain %d\n", len);
        buffer[i] = len;
        //printf("buffer[%d] = %u\n", i, buffer[i]);
        i = i+1;

        memcpy(buffer+i, domain_in_packet, len);
        i=i+len;

        domain_in_packet = str_ptr + 1;
    }

    //what remains is the last chars after with on dots
    len = strlen(domain) - (domain_in_packet - domain);
    buffer[i] = len;
   //printf("buffer[%d] = %u\n", i, buffer[i]);
    i =i+1;

    memcpy(buffer+i, domain_in_packet, len);
    i=i+len;

    buffer[i] = 0;
    //printf("buffer[%d] = %u\n", i, buffer[i]);
    i += 1;

    *buff += i;
    return 0;
}

//put the answer struct into the buff
int encode_resource_record(uint8_t **buff, struct dns_answer *r){
 
    while(r){
        encode_domain_name(buff, r->name);
        put_16bits(buff, r->type);
        put_16bits(buff, r->class);
        put_32bits(buff, r->ttl);
        put_16bits(buff, r->rdlength);

        if(r->type == 1){
            //printf("they need A record\n'");
            for(int i=0; i<4; i++){
                put_8bits(buff, r->addr[i]);
            }
        }
        else{
            printf("i only resolve A record\n");
        }
        r = r->next;
    }
    return 0;
}

//return 0 on failure and 1 on success
//put the packet struct into the buff
int encode_packet(uint8_t **buff, struct dns_r_packet *r_packet){

    encode_header (buff, r_packet);

    struct dns_question *q;
    q= r_packet->r_question;
    while(q){
        encode_domain_name(buff, q->qname);
        put_16bits(buff, q->qtype);
        put_16bits(buff, q->qclass);
        q=q->next;
    }
    int rc=0;
    rc |= encode_resource_record(buff, r_packet->r_answer);
    return rc;
}

int send_packet(int fd, uint8_t *buff, int size){

    const uint8_t *begin = buff;//saves where buff first points to
    int buflen; //to store length traveled by buffer
/*
//print the initial contents of the buffer
    for(int j=0; j< size; j++){
        printf("%u ", begin[j]);
    }
    printf("\n");
*/   

    struct dns_r_packet r_packet;
    memset(&r_packet, 0, sizeof(struct dns_r_packet));

//store contents of buff in r_packet
    if (decode_packet( buff, &r_packet, size) != 0) {
      printf("not decoded properly\n");
    }

//prints the r_packet   
    r_packet.r_answer= NULL;
    print_packet(&r_packet);

//rewrite the contents of header stuct and set response struct for each query
    //printf("r_packet is before resolve query  %d\n", r_packet);
    resolve_query(&r_packet);

//put the prepared structs into buff
    encode_packet(&buff, &r_packet);

/*
//print the contents of the buffer
    for(int j=0; j< 100; j++){
        printf("%u ", begin[j]);
    }
    printf("\n");
*/

//print contents of the packet
    print_packet(&r_packet);

//find and return length of buff 
    buflen= (buff-begin); 
    return buflen;
} 
