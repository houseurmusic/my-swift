# To change this template, choose Tools | Templates
# and open the template in the editor.

#chunk format: "<msg><end_char><padding><number of excess chars><final char>
#delim is the padding character used, end_msg_char = to the char used if your chunk
#has an character that denotes its end. Its to double check a sucessful trim
#import sys
#sys.path.append( 'C:\Users\ajmedeiros\Documents\swift\swift\encryption-middleware' )


def padder(text, div, pad = chr(0)):
    size = (div - len(text) % div) + len(text)
    diff = size - len(text)
    padded_text = text + pad * diff
    return padded_text

text = "a"
padded_text = padder(text, 5, '-')
print padded_text
print padded_text.rstrip('-')
