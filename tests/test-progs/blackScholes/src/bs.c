/*
 * Copyright (c) 2006 The Regents of The University of Michigan
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met: redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer;
 * redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution;
 * neither the name of the copyright holders nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include <math.h>
#include <stdio.h>
#include <stdlib.h>

double sqrt_ (double a){
  return a * a;
}

double exp_(double a){
  int i;
  double r = 1;
  for (i = 0; i < a; i++){
    r *= 2.7;
  }

  return r;
}

double log_(double a){
  return a / 9.9;
}

double pow_(double a, int b){
  int i;
  double r = a;
  for (i = 0; i < b; i++){
    r *= a;
  }

  return r;
}



double Normal(double zz)
{
  //cdf of 0 is 0.5
  if (zz == 0)
    {
      return 0.5;
    }

  double z = zz;  //zz is input variable,  use z for calculations

  if (zz < 0)
    z = -zz;  //change negative values to positive

  //set constants
  double p = 0.2316419;
  double b1 = 0.31938153;
  double b2 = -0.356563782;
  double b3 = 1.781477937;
  double b4 = -1.821255978;
  double b5 = 1.330274428;

  //CALCULATIONS
  double f = 1 / sqrt(2 * 3.14);
  double ff = exp(-pow(z, 2) / 2) * f;
  double s1 = b1 / (1 + p * z);
  double s2 = b2 / pow((1 + p * z), 2);
  double s3 = b3 / pow((1 + p * z), 3);
  double s4 = b4 / pow((1 + p * z), 4);
  double s5 = b5 / pow((1 + p * z), 5);

  //sz is the right-tail approximation
  double  sz = ff * (s1 + s2 + s3 + s4 + s5);

  double rz;
  //cdf of negative input is right-tail of input's absolute value
  if (zz < 0)
    rz = sz;

  //cdf of positive input is one minus right-tail
  if (zz > 0)
    rz = (1 - sz);


  return rz;
}


// double Normal(double zz){
//     return zz;
// }

double callValue(double strike, double s, double sd, double r, double days)
{
  double ls = log(s);
  double lx = log(strike);
  double t = days / 365;
  double sd2 = pow(sd, 2);
  double n = (ls - lx + r * t + sd2 * t / 2);
  double sqrtT = sqrt(days / 365);
  double d = sd * sqrtT;
  double d1 = n / d;
  double d2 = d1 - sd * sqrtT;
  double nd1 = Normal(d1);
  double nd2 = Normal(d2);
  return s * nd1 - strike * exp(-r * t) * nd2;
}

double putValue(double strike, double s, double sd, double r, double days)
{
  double ls = log(s);
  double lx = log(strike);
  double t = days / 365;
  double sd2 = pow(sd, 2);
  double n = (ls - lx + r * t + sd2 * t / 2);
  double sqrtT = sqrt(days / 365);
  double d = sd * sqrtT;
  double d1 = n / d;
  double d2 = d1 - sd * sqrtT;
  double nd1 = Normal(d1);
  double nd2 = Normal(d2);
  return strike * exp(-r * t) * (1 - nd2) - s * (1 - nd1);
}

int main(int argc, char *argv[])
{
  printf("start main\n");

  double strike_price = atof(argv[1]);
  double asset_price = atof(argv[2]);
  double standard_deviation = atof(argv[3]);
  double risk_free_rate = atof(argv[4]);
  double days_to_exp = atof(argv[5]);
  int loop = atoi(argv[6]);
  int to_wait = atoi(argv[7]);


  /*
  double strike_price = 100;
  double asset_price = 2;
  double standard_deviation = 3;
  double risk_free_rate = 4;
  double days_to_exp = 5;
  int loop = 100000;
  int to_wait = 1;
  */

  printf("iterate: %d\n", loop);
  printf("Strike Price: %f \n", strike_price);
  printf("Asset Price:  %f \n", asset_price);
  printf("Std Dev:      %f \n", standard_deviation);
  printf("Risk Free:    %f \n", risk_free_rate);
  printf("Days to Exp:  %f \n", days_to_exp);

  int i;
  double pv = strike_price;
  double cv = strike_price;
  for (i = 0; i < loop; i++){
    if ((i % 5000) == 0 ){
      printf("%d th iteration\n", i);
    }
    pv = putValue(strike_price, pv, standard_deviation,\
                  risk_free_rate, days_to_exp);

    cv = callValue(cv, asset_price, standard_deviation,\
                   risk_free_rate, days_to_exp);
  }
  printf("Put Value:    %f \n", pv);
  printf("Call Value:   %f \n", cv);

  // this is for the first cpu to wait for other cpus finish.

  if (to_wait){
    printf("waiting...\n");
    for (i = 0; i < 20; i++){
      cv = callValue(cv, asset_price, standard_deviation,	\
                     risk_free_rate, days_to_exp);
    }
    printf("result for waiting: %f\n", cv);
  }


  return 0;
}
