import dayjs from 'dayjs';

interface ModuleLoggerInterface {
  log(message: string, ...optionalParams: unknown[]): void;
  info(message: string, ...optionalParams: unknown[]): void;
  error(message: string, ...optionalParams: unknown[]): void;
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

  log(message: string, ...optionalParams: unknown[]) {
    !this.#quiet && this.#module.log(this.message(message), ...optionalParams);
  }

  info(message: string, ...optionalParams: unknown[]) {
    !this.#quiet && this.#module.info(this.message(message), ...optionalParams);
  }

  error(message: string, ...optionalParams: unknown[]) {
    !this.#quiet && this.#module.error(this.message(message), ...optionalParams);
  }

  mute(state = true) {
    this.#quiet = state;
  }

  private message = (message: string) => `[${dayjs().format('YYYY-MM-DD hh:mm:ss')}][hrbac] ${message}`;
}

export { SimpleLogger };
export default new SimpleLogger();
