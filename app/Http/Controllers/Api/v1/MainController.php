<?php

namespace App\Http\Controllers\Api\v1;

use Illuminate\Http\Request;
use Laravel\Lumen\Routing\Controller as BaseController;
use Illuminate\Support\Facades\{Log, Validator};
use phpseclib3\Crypt\{RSA, PublicKeyLoader};


class MainController extends BaseController

{
  /**
   * @param  Request  $request
   * @return Response
   */


  public function index(Request $request)
  {
    //tokenTTL
    $tokenExpire = time() + env('TOKEN_TTL');

    // Validation
    $validator = Validator::make($request->all(), [
      'cvc' => [
        'required',
        'digits:3'
      ],
      'cardholder' => [
        'required',
        'string'
      ],
      'expire' => [
        'required',
        'date_format:m/y'
      ],
      'pan' => [
        'required',
        'max:16',
        //проверяет по алгоритму Луна 
        function ($attribute, $value, $fail) {
          $number = strrev(preg_replace('/[^\d]+/', '', $value));
          $sum = 0;
          for ($i = 0, $j = strlen($number); $i < $j; $i++) {
            if (($i % 2) == 0) {
              $val = $number[$i];
            } else {
              $val = $number[$i] * 2;
              if ($val > 9) {
                $val -= 9;
              }
            }
            $sum += $val;
          }

          if (($sum % 10) === 0) {
            return 1;
          } else {
            $fail('The ' . $attribute . ' is invalid.');
          }
        },
      ],
    ], [
      'required' => 'The :attribute field is required.',
      'max' => 'the :attribute max 16'
    ]);
    if ($validator->fails()) {
      $error = $validator->errors()->first();

      Log::build([
        'driver' => 'single',
        'path' => storage_path('logs/custom.log'),
      ])->error($error);

      return [
        'success' => 0,
        'message' => $error,
        'error' => 400,
      ];
    }

    //добавляем токен в реквест
    $request->request->add(['tokenExpire' => $tokenExpire]);
    //шифруем
    $encryptedLog = $this->cypherRequest($request);


    return response()->json([
      'pan' => substr($request->pan, 0, 4) . '**' . substr($request->pan, 8, 4),
      'token' => $encryptedLog
    ]);
  }

  public function cypherRequest($request)
  {
    $private = RSA::createKey();

    $publickey = $private->getPublicKey();

    $key = PublicKeyLoader::load($publickey);
    $key = $key->withPadding(RSA::ENCRYPTION_PKCS1);

    $encryptedLog =  base64_encode($key->encrypt($request->tokenExpire));

    Log::build([
      'driver' => 'single',
      'path' => storage_path('logs/custom.log'),
    ])->info($encryptedLog);

    return $encryptedLog;
  }
}