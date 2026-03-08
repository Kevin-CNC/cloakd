import * as path from 'path';
import * as glob from 'glob';
const Mocha = require('mocha');

export function run(): Promise<void> {
    const mocha = new Mocha({
        ui: 'tdd',
        color: true,
    });

    const testsRoot = path.resolve(__dirname);

    return new Promise((resolve, reject) => {
        try {
            const files = glob.sync('**/*.test.js', { cwd: testsRoot });
            for (const file of files) {
                mocha.addFile(path.resolve(testsRoot, file));
            }

            mocha.run((failures: number) => {
                if (failures > 0) {
                    reject(new Error(`${failures} test(s) failed.`));
                } else {
                    resolve();
                }
            });
        } catch (error) {
            reject(error);
        }
    });
}
