import http from 'k6/http';
import { sleep } from 'k6';

export const options = {
    vus: 10000,
    duration: '2m',
};

export default function () {

    const payload = JSON.stringify({
        username: `user_${__VU}_${__ITER}`,
        password: 'password'
    });

    const params = {
        headers: {
            'Content-Type': 'application/json',
        },
    };

    http.post(
        'https://2o124a61je.execute-api.ap-south-1.amazonaws.com/Prod/auth/register',
        payload,
        params
    );

    sleep(1);
}