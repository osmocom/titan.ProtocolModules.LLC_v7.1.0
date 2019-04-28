///////////////////////////////////////////////////////////////////////////////
//
// Copyright (c) 2000-2019 Ericsson Telecom AB
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Eclipse Public License v2.0
// which accompanies this distribution, and is available at
// https://www.eclipse.org/org/documents/epl-2.0/EPL-2.0.html
///////////////////////////////////////////////////////////////////////////////
//
//  File:               LLC_EncDec.cc
//  Rev:                R3A
//  Prodnr:             CNL 113 577
//  Updated:            2008-01-22
//  Contact:            http://ttcn.ericsson.se
//  Reference:          3GPP TS 44.064 7.1.0

#include "LLC_Types.hh"
#include <string.h>

// GIVEN IN CODE RECEIVED FROM ERV
#define CRC_POLY_LLC2  0xad85dd

// GIVEN IN SPECIFICATION
//#define CRC_POLY_LLC2  0xbba1b5

#define TABLE_LENGTH  256

// For UI frames if PM bit is 0 (unprotected) then CRC will be calculated over Header + N202 octets
#define N202 4

unsigned int mCRCTable[TABLE_LENGTH] = {
  0x00000000, 0x00d6a776, 0x00f64557, 0x0020e221, 0x00b78115, 0x00612663, 0x0041c442, 0x00976334,
  0x00340991, 0x00e2aee7, 0x00c24cc6, 0x0014ebb0, 0x00838884, 0x00552ff2, 0x0075cdd3, 0x00a36aa5,
  0x00681322, 0x00beb454, 0x009e5675, 0x0048f103, 0x00df9237, 0x00093541, 0x0029d760, 0x00ff7016,
  0x005c1ab3, 0x008abdc5, 0x00aa5fe4, 0x007cf892, 0x00eb9ba6, 0x003d3cd0, 0x001ddef1, 0x00cb7987,
  0x00d02644, 0x00068132, 0x00266313, 0x00f0c465, 0x0067a751, 0x00b10027, 0x0091e206, 0x00474570,
  0x00e42fd5, 0x003288a3, 0x00126a82, 0x00c4cdf4, 0x0053aec0, 0x008509b6, 0x00a5eb97, 0x00734ce1,
  0x00b83566, 0x006e9210, 0x004e7031, 0x0098d747, 0x000fb473, 0x00d91305, 0x00f9f124, 0x002f5652,
  0x008c3cf7, 0x005a9b81, 0x007a79a0, 0x00acded6, 0x003bbde2, 0x00ed1a94, 0x00cdf8b5, 0x001b5fc3,
  0x00fb4733, 0x002de045, 0x000d0264, 0x00dba512, 0x004cc626, 0x009a6150, 0x00ba8371, 0x006c2407,
  0x00cf4ea2, 0x0019e9d4, 0x00390bf5, 0x00efac83, 0x0078cfb7, 0x00ae68c1, 0x008e8ae0, 0x00582d96,
  0x00935411, 0x0045f367, 0x00651146, 0x00b3b630, 0x0024d504, 0x00f27272, 0x00d29053, 0x00043725,
  0x00a75d80, 0x0071faf6, 0x005118d7, 0x0087bfa1, 0x0010dc95, 0x00c67be3, 0x00e699c2, 0x00303eb4,
  0x002b6177, 0x00fdc601, 0x00dd2420, 0x000b8356, 0x009ce062, 0x004a4714, 0x006aa535, 0x00bc0243,
  0x001f68e6, 0x00c9cf90, 0x00e92db1, 0x003f8ac7, 0x00a8e9f3, 0x007e4e85, 0x005eaca4, 0x00880bd2,
  0x00437255, 0x0095d523, 0x00b53702, 0x00639074, 0x00f4f340, 0x00225436, 0x0002b617, 0x00d41161,
  0x00777bc4, 0x00a1dcb2, 0x00813e93, 0x005799e5, 0x00c0fad1, 0x00165da7, 0x0036bf86, 0x00e018f0,
  0x00ad85dd, 0x007b22ab, 0x005bc08a, 0x008d67fc, 0x001a04c8, 0x00cca3be, 0x00ec419f, 0x003ae6e9,
  0x00998c4c, 0x004f2b3a, 0x006fc91b, 0x00b96e6d, 0x002e0d59, 0x00f8aa2f, 0x00d8480e, 0x000eef78,
  0x00c596ff, 0x00133189, 0x0033d3a8, 0x00e574de, 0x007217ea, 0x00a4b09c, 0x008452bd, 0x0052f5cb,
  0x00f19f6e, 0x00273818, 0x0007da39, 0x00d17d4f, 0x00461e7b, 0x0090b90d, 0x00b05b2c, 0x0066fc5a,
  0x007da399, 0x00ab04ef, 0x008be6ce, 0x005d41b8, 0x00ca228c, 0x001c85fa, 0x003c67db, 0x00eac0ad,
  0x0049aa08, 0x009f0d7e, 0x00bfef5f, 0x00694829, 0x00fe2b1d, 0x00288c6b, 0x00086e4a, 0x00dec93c,
  0x0015b0bb, 0x00c317cd, 0x00e3f5ec, 0x0035529a, 0x00a231ae, 0x007496d8, 0x005474f9, 0x0082d38f,
  0x0021b92a, 0x00f71e5c, 0x00d7fc7d, 0x00015b0b, 0x0096383f, 0x00409f49, 0x00607d68, 0x00b6da1e,
  0x0056c2ee, 0x00806598, 0x00a087b9, 0x007620cf, 0x00e143fb, 0x0037e48d, 0x001706ac, 0x00c1a1da,
  0x0062cb7f, 0x00b46c09, 0x00948e28, 0x0042295e, 0x00d54a6a, 0x0003ed1c, 0x00230f3d, 0x00f5a84b,
  0x003ed1cc, 0x00e876ba, 0x00c8949b, 0x001e33ed, 0x008950d9, 0x005ff7af, 0x007f158e, 0x00a9b2f8,
  0x000ad85d, 0x00dc7f2b, 0x00fc9d0a, 0x002a3a7c, 0x00bd5948, 0x006bfe3e, 0x004b1c1f, 0x009dbb69,
  0x0086e4aa, 0x005043dc, 0x0070a1fd, 0x00a6068b, 0x003165bf, 0x00e7c2c9, 0x00c720e8, 0x0011879e,
  0x00b2ed3b, 0x00644a4d, 0x0044a86c, 0x00920f1a, 0x00056c2e, 0x00d3cb58, 0x00f32979, 0x00258e0f,
  0x00eef788, 0x003850fe, 0x0018b2df, 0x00ce15a9, 0x0059769d, 0x008fd1eb, 0x00af33ca, 0x007994bc,
  0x00dafe19, 0x000c596f, 0x002cbb4e, 0x00fa1c38, 0x006d7f0c, 0x00bbd87a, 0x009b3a5b, 0x004d9d2d
};


static void BuildCrc24Table()
{
  unsigned int i,j;
  unsigned int reg;

  for( i = 0; i < TABLE_LENGTH; i++ )
  {
    reg = i;
    for( j = 8; j > 0; j-- )
    {
      if( reg & 1 )
      {
        reg = (reg>>1) ^ (unsigned int) CRC_POLY_LLC2;
      }
      else
      {
        reg >>= 1;
      }
    }
    reg &= 0x00ffffffL;

    mCRCTable[i] = (unsigned int)reg;
    //printf("mCRCTable[%d]= 0x%08x\n",i,mCRCTable[i]);
  }
}

//---------------------------------------------------------------------------------------

unsigned int  Calculate_CRC(TTCN_Buffer& pdu)
{
  const unsigned char* loc_pdu = pdu.get_data();

//BuildCrc24Table();

//TTCN_Logger::begin_event(TTCN_DEBUG);
//TTCN_Logger::log_event("mCRCTable[%d]= %d\n",255,mCRCTable[255]);
//TTCN_Logger::log_event("mCRCTable[%d]= 0x%08x (%u)",255,mCRCTable[255]);
//TTCN_Logger::log_event("\n");
//TTCN_Logger::end_event();

  unsigned int reg = 0xFFFFFF;
  unsigned int length = pdu.get_len();

  if(((loc_pdu[1] >>5) & 0x07) == 0x06)     //UI frame
  {
    if ((loc_pdu[2] & 0x01) == 0x00)        // PM bit is 0 (unprotected)
    {
      if(length > 3 + N202)                 // pdu length is longer than header + N202
      {
        length = 3 + N202;                  // length = header length + N202
      }
    }
  }

  while ( length--)
  {
    reg = ((reg>>8) & 0x00ffff)^mCRCTable[(reg^*((unsigned char*)loc_pdu++)) & 0xffL];
  }

  reg ^= 0xffffffL;

  reg = ((reg >> 16) & 0x000000ff)+ ((reg)  & 0x0000ff00) + ((reg <<16 )& 0x00ff0000);

  return  reg & 0x00ffffffL;
}

//---------------------------------------------------------------------------------------

namespace LLC__Types {

OCTETSTRING enc__PDU__LLC(const PDU__LLC& pdu)
{
  TTCN_Buffer bb;
  PDU__LLC pdu2(pdu);

  if (pdu2.get_selection() == PDU__LLC::ALT_pDU__LLC__UI)
  {
    if ( pdu2.pDU__LLC__UI().fCS().ispresent())
    {
      if ( pdu2.pDU__LLC__UI().fCS() == int2oct(0,3) )
      { // IF ZERO, THEN ENCODER NEEDS TO GENERATE CRC
        pdu2.pDU__LLC__UI().fCS() = OMIT_VALUE;
        pdu2.encode(PDU__LLC_descr_ ,bb, TTCN_EncDec::CT_RAW);
        unsigned int crcBuffer = Calculate_CRC(bb);
        bb.put_os(int2oct(crcBuffer,3));
        return OCTETSTRING (bb.get_len(), bb.get_data());
      }
      else
      { // IF ENCODER SENDS OUT NONZERO CRC GIVEN IN TTCN TEMPLATE
        pdu2.encode(PDU__LLC_descr_ ,bb, TTCN_EncDec::CT_RAW);
        return OCTETSTRING (bb.get_len(), bb.get_data());
      }
    }
    else
    { //FCS OMIT
      pdu2.encode(PDU__LLC_descr_ ,bb, TTCN_EncDec::CT_RAW);
      unsigned int crcBuffer = Calculate_CRC(bb);
      bb.put_os(int2oct(crcBuffer,3));
      return OCTETSTRING (bb.get_len(), bb.get_data());
    }
  }
  else if (pdu2.get_selection() == PDU__LLC::ALT_pDU__LLC__U)
  {
    if (pdu2.pDU__LLC__U().information__field__U().get_selection() ==  Information__field__U::ALT_uA)
    {
      int record_of_size = pdu2.pDU__LLC__U().information__field__U().uA().size_of();

      for (int  i = 0; i < (record_of_size) ; i++)
      { // AUTOMATICALLY CALCULATE WHICH LENGTH FORMAT SHOULD BE USED AND CHANGE SHORT LENGTH FORM
        // TO LONG LENGTH FORM IF NECESSARY WHEN L3 PDU IS INCLUDED
        if ( pdu2.pDU__LLC__U().information__field__U().uA()[i].typefield() == int2bit(11,5) )
        {
          if( pdu2.pDU__LLC__U().information__field__U().uA()[i].xID__Data().l3param().lengthof() > 3)
          {
            pdu2.pDU__LLC__U().information__field__U().uA()[i].xID__length().long__len() =
              pdu2.pDU__LLC__U().information__field__U().uA()[i].xID__Data().l3param().lengthof();
          }
        }
      }
    }

    if (pdu2.pDU__LLC__U().information__field__U().get_selection() ==  Information__field__U::ALT_sABM)
    {
      int record_of_size = pdu2.pDU__LLC__U().information__field__U().sABM().size_of();

      for (int  i = 0; i < (record_of_size) ; i++)
      { // AUTOMATICALLY CALCULATE WHICH LENGTH FORMAT SHOULD BE USED AND CHANGE SHORT LENGTH FORM
        // TO LONG LENGTH FORM IF NECESSARY WHEN L3 PDU IS INCLUDED
        if ( pdu2.pDU__LLC__U().information__field__U().sABM()[i].typefield() == int2bit(11,5) )
        {
          if( pdu2.pDU__LLC__U().information__field__U().sABM()[i].xID__Data().l3param().lengthof() > 3)
          {
            pdu2.pDU__LLC__U().information__field__U().sABM()[i].xID__length().long__len() =
              pdu2.pDU__LLC__U().information__field__U().sABM()[i].xID__Data().l3param().lengthof();
          }
        }
      }
    }

    if (pdu2.pDU__LLC__U().information__field__U().get_selection() ==  Information__field__U::ALT_xID)
    {
      int record_of_size = pdu2.pDU__LLC__U().information__field__U().xID().size_of();

      for (int  i = 0; i < (record_of_size) ; i++)
      { // AUTOMATICALLY CALCULATE WHICH LENGTH FORMAT SHOULD BE USED AND CHANGE SHORT LENGTH FORM
        // TO LONG LENGTH FORM IF NECESSARY WHEN L3 PDU IS INCLUDED
        if ( pdu2.pDU__LLC__U().information__field__U().xID()[i].typefield() == int2bit(11,5) )
        {
          if( pdu2.pDU__LLC__U().information__field__U().xID()[i].xID__Data().l3param().lengthof() > 3)
          {
            pdu2.pDU__LLC__U().information__field__U().xID()[i].xID__length().long__len() =
             pdu2.pDU__LLC__U().information__field__U().xID()[i].xID__Data().l3param().lengthof();
          }
        }
      }
    }

    if ( pdu2.pDU__LLC__U().fCS().ispresent())
    {
      if ( pdu2.pDU__LLC__U().fCS() == int2oct(0,3) )  // IF ENCODER NEEDS TO GENERATE CRC
      {
        pdu2.pDU__LLC__U().fCS() = OMIT_VALUE;
        pdu2.encode(PDU__LLC_descr_ ,bb, TTCN_EncDec::CT_RAW);
        unsigned int crcBuffer = Calculate_CRC(bb);
        bb.put_os(int2oct(crcBuffer,3));
        return OCTETSTRING (bb.get_len(), bb.get_data());
      }
      else
      { // IF ENCODER SENDS OUT NONZERO CRC GIVEN IN TTCN TEMPLATE
        pdu2.encode(PDU__LLC_descr_ ,bb, TTCN_EncDec::CT_RAW);
        return OCTETSTRING (bb.get_len(), bb.get_data());
      }
    }
    else
    {    //FCS OMIT
      pdu2.encode(PDU__LLC_descr_ ,bb, TTCN_EncDec::CT_RAW);
      unsigned int crcBuffer = Calculate_CRC(bb);
      bb.put_os(int2oct(crcBuffer,3));
      return OCTETSTRING (bb.get_len(), bb.get_data());
    }
  }
  else
  {
    TTCN_error("Can not encode LLC PDU");  //Neither UI NOR U
    return  OCTETSTRING (bb.get_len(), bb.get_data()); // this is dummy to avoid warning during compilation
  }
}


OCTETSTRING enc__PDU__LLC(const PDU__LLC_template& pdu)
{
  return enc__PDU__LLC(pdu.valueof());
}


PDU__LLC dec__PDU__LLC(const OCTETSTRING& stream, const BOOLEAN& checkFCS)
{
  PDU__LLC retv;
  TTCN_Buffer bb;

  size_t datalength = stream.lengthof()-3;
  bb.put_s(datalength,(const unsigned char *)stream);
  retv.decode(PDU__LLC_descr_, bb, TTCN_EncDec::CT_RAW);

  const unsigned char * CRC_AS_RECEIVED = (const unsigned char *)stream+datalength;

  if(checkFCS)
  {
    // FILL CRC octets with zeroes if CRC is OK
    OCTETSTRING crc = int2oct(0,3);
    unsigned int CRC_CALCULATED = Calculate_CRC(bb);

    // COMPARE CRC RECEIVED IN LLC PDU WITH CRC CALCULATED FROM LLC PDU
    if( (CRC_AS_RECEIVED[ 0 ] != (CRC_CALCULATED & 0xff0000  ) >> 16) ||
        (CRC_AS_RECEIVED[ 1 ] != (CRC_CALCULATED & 0xff00    ) >> 8) ||
         CRC_AS_RECEIVED[ 2 ] != (CRC_CALCULATED & 0xff      )     )
    {
      TTCN_warning("CRC ERROR IN LLC PDU");  // CRC IS NOT AS EXPECTED
      crc=OCTETSTRING(3,CRC_AS_RECEIVED);
    }

    if (retv.get_selection() == PDU__LLC::ALT_pDU__LLC__UI)
    {
      retv.pDU__LLC__UI().fCS() = crc;
    }

    if (retv.get_selection() == PDU__LLC::ALT_pDU__LLC__U)
    {
      retv.pDU__LLC__U().fCS() = crc;
    }
  }
  else
  {
    if (retv.get_selection() == PDU__LLC::ALT_pDU__LLC__UI)
    {
      retv.pDU__LLC__UI().fCS() = OCTETSTRING(3,CRC_AS_RECEIVED);
    }
    else if (retv.get_selection() == PDU__LLC::ALT_pDU__LLC__U)
    {
      retv.pDU__LLC__U().fCS() = OCTETSTRING(3,CRC_AS_RECEIVED);
    }
  }


  return retv;
}

}//namespace
