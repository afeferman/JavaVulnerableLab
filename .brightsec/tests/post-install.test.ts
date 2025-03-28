import { test, before, after } from 'node:test';
import { Severity, AttackParamLocation, HttpMethod } from '@sectester/scan';
import { SecRunner } from '@sectester/runner';

let runner!: SecRunner;

before(async () => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME!,
    projectId: process.env.BRIGHT_PROJECT_ID!
  });

  await runner.init();
});

after(() => runner.clear());

const timeout = 40 * 60 * 1000;
const baseUrl = process.env.BRIGHT_TARGET_URL!;

test('POST /install', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['sqli', 'open_database', 'csrf', 'xss', 'excessive_data_exposure', 'full_path_disclosure'],
      attackParamLocations: [AttackParamLocation.BODY]
    })
    .threshold(Severity.CRITICAL)
    .timeout(timeout)
    .run({
      method: HttpMethod.POST,
      url: `${baseUrl}/install`,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'dburl=jdbc:mysql://localhost:3306/&jdbcdriver=com.mysql.jdbc.Driver&dbuser=root&dbpass=password&dbname=vulnerable_db&siteTitle=Vulnerable Lab&adminuser=admin&adminpass=adminpass&setup=1'
    });
});
