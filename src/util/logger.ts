import dayjs from 'dayjs';

interface ModuleLoggerInterface {
  error(message: string, ...optionalParams: never[]): void;
  info(message: string, ...optionalParams: never[]): void;
  log(message: string, ...optionalParams: never[]): void;
}

type OptionsType = {
  module?: ModuleLoggerInterface;
  quiet?: boolean;
};

class SimpleLogger {
  #module: ModuleLoggerInterface;
  #quiet: boolean;

  constructor(options: OptionsType = { quiet: true }) {
    this.#module = options?.module ?? console;
    this.#quiet = Boolean(options?.quiet);
  }

  log(message: string, ...optionalParams: never[]) {
    !this.#quiet && this.#module.log(this.message(message), ...optionalParams);
  }

  info(message: string, ...optionalParams: never[]) {
    !this.#quiet && this.#module.info(this.message(message), ...optionalParams);
  }

  error(message: string, ...optionalParams: never[]) {
    !this.#quiet && this.#module.error(this.message(message), ...optionalParams);
  }

  private message = (message: string) => `[${dayjs().format('YYYY-MM-DD hh:mm:ss')}][hrbac] ${message}`;
}

export const logger = new SimpleLogger();
