import {Client} from "./mysql.js.deno.ts";

const mysql = new Client();
const mysqlClient = await mysql.connect({
	username: 'root',
	db: 'test',
	// hostname is the full URL to your pre-created Cloudflare Tunnel, see documentation here:
	// https://developers.cloudflare.com/cloudflare-one/connections/connect-apps/create-tunnel
	hostname: '127.0.0.1',
	password: '', // use a secret to store passwords
});

// Query the database.
const param = 42;
const result = await mysqlClient.query('SELECT ?;', [param]);

console.log(result)
