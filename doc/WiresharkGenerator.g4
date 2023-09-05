// ANTLR grammar for the wireshark generator
grammar WiresharkGenerator;

protocol : protoDecl+ ;

protoDecl : dissectorTableDecl ';'
          | endianDecl ';'
	        | protoDetailsDecl ';'
	        | dissectorEntryDecl ';'
	        | enumDecl ';'
	        | structDecl ';'
	        | typeDef ';'
	        ;

endianDecl : 'endian' '=' (E_BIG | E_LITTLE) ;

// A dissector table entry--too specific
dissectorTableDecl : 'dissectorTable' '[' STRING ',' STRING ']' '=' ID ;
protoDetailsDecl   : 'protoDetails' '=' '{' STRING ',' STRING ',' STRING '}' ;
dissectorEntryDecl : 'dissectorEntry' ID '=' ID ;

enumEltDecl : INT '=' ID ( ':' STRING)?
           	| 'default' '=' STRING
           	;

enumDecl:  'enum' ID ( ':' ID )? '{' enumEltDecl (',' enumEltDecl )* (',')? '}' ;

typeDef : 'typedef' ID ID ('[' INT ']')? ;

// A case Decl can be a case statememt or a default. The IDs must be defined
// in an enum ... do we want to complicate the grammar to allow integer or
// hex values?

param  : INT | STRING | ID | fieldPath;
params : param ( ',' param )* ;

function: ID ( '(' params ')' );

// Should use the details below
caseDeclDetails : function
                | ID
                | structEltDecl
                | '{' ( structEltDecl ';' )+ '}'
 //             | ID (STRING | ID)
 //             | ID (ID | STRING) '[' (INT | switchStructEltCtrl) ']'
                | 'void' ;

//defaultDecl: 'default' ':' caseDeclDetails ';' ;

// For convenience we allow ID | INT after 'case'?
caseLabel : ID | INT ;
caseDecl  : ( 'case' caseLabel | 'default' ) ':' caseDeclDetails ';'
	;

// A fieldpath is a series of IDs or STRINGs separated by '/' and perhaps
// preceded by '../' to go back up one level.
field     : ID | STRING ;
fieldPath : startSym=('../' | '/')? field ( '/' field)* ;

switchStructEltCtrl : fieldPath // Can be a path to a field.
	                  | fieldPath op=('!='|'>='|'<='|'=='|'<<'|'>>'|'+'|'-'|'&') (INT | ID)
	                  ;

// A switch decl allows structures to change depending on earlier fields
// This is unnamed because it is not a type and it will always want to
// refer to an earlier field in the same structure or a parent structure.
// Some switchStructEltCtrl item will have to be filtered out after
// parsing, because a string that matches no field would be illegal.
switchDecl : 'switch' '(' switchStructEltCtrl ')' '{' caseDecl+ '}' ;

// An element in a struct declaration can be external, but then must
// Specify a dissector table ...
externEltDecl : 'extern' '[' STRING ']' ID (ID | STRING) ;

// We want to allow a field to carve out some contiguous bits from the
// containing type and apply a defined type to that. Eg:
// uint8:7-4:some-def some-field-name -- this is a 4-bit field
// or
// uint8:7:some-other-def some-field-name -- this is a 1-bit field
localEltDeclCont: ':' INT ( '-' INT)? ':' ID (ID | STRING) ;

localEltDecl : ID (ID | STRING)
	           | ID localEltDeclCont  ( ',' localEltDeclCont)*
	           ;

// Some switchStructEltCtrl items will have to be filtered out after
// parsing, because a string that matches no field would be illegal.
arrayEltDecl : ID (ID | STRING) '[' (INT | switchStructEltCtrl) ']' ;

structEltDecl : externEltDecl
	            | localEltDecl
	            | arrayEltDecl
	            | switchDecl
	            ;

structDecl : 'struct' ID '{' ( structEltDecl ';' )+ '}' ;

UP_ONE : '../' ;
ABS : '/' ;

NE : '!=' ;
GE : '>=' ;
LE : '<=' ;
EQ : '==' ;
LS : '<<' ; // Left shift
RS : '>>' ; // Right shift
SUB : '-' ;
ADD : '+' ;
MUL : '*' ;
AND : '&' ; // Bitwise and

E_BIG : 'big' ;
E_LITTLE : 'little' ;
STRING: '"'.*?'"' ;                //Embedded quotes?
COMMENT: '#' .*? [\n\r] -> skip ;  // Discard comments for now
ID :   [a-zA-Z][a-zA-Z0-9_]* ;
WS :   [ \t\n\r]+ -> skip ;
INT : '0x' [0-9a-fA-F]+
      | [0-9]+ ;       // Hex or decimal numbers
