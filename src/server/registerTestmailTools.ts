import type { TestmailService } from "../testmail/TestmailService.js";
import { toolContract } from "../contracts/toolContracts.js";
import type { EvidenceMcpServer } from "./EvidenceMcpServer.js";
import { toolRegistrationOptions } from "./toolRegistrationOptions.js";

export interface TestmailToolRegistration {
  readonly server: EvidenceMcpServer;
  readonly testmail: TestmailService;
}

/**
 * Register the disposable-mailbox plane: allocate mailboxes, wait for
 * verification mail with extraction, read full messages, and release. The
 * providers are keyless, so there is no availability gate; failures surface
 * as typed provider errors.
 */
export const registerTestmailTools = ({
  server,
  testmail,
}: TestmailToolRegistration): void => {
  const listContract = toolContract("testmail_list_providers");
  server.registerTool(
    listContract.name,
    toolRegistrationOptions(listContract),
    async (_input, context) =>
      server.delivery.toCallToolResult(
        await testmail.listProviders(context.mcpReq.signal),
        listContract,
      ),
  );
  const createContract = toolContract("testmail_create_mailbox");
  server.registerTool(
    createContract.name,
    toolRegistrationOptions(createContract),
    async (input, context) =>
      server.delivery.toCallToolResult(
        await testmail.createMailbox(input, context.mcpReq.signal),
        createContract,
      ),
  );
  const waitContract = toolContract("testmail_wait_for_mail");
  server.registerTool(
    waitContract.name,
    toolRegistrationOptions(waitContract),
    async (input, context) =>
      server.delivery.toCallToolResult(
        await testmail.waitForMail(input, context.mcpReq.signal),
        waitContract,
      ),
  );
  const readContract = toolContract("testmail_read_message");
  server.registerTool(
    readContract.name,
    toolRegistrationOptions(readContract),
    async (input, context) =>
      server.delivery.toCallToolResult(
        await testmail.readMessage(input, context.mcpReq.signal),
        readContract,
      ),
  );
  const deleteContract = toolContract("testmail_delete_mailbox");
  server.registerTool(
    deleteContract.name,
    toolRegistrationOptions(deleteContract),
    async (input, context) =>
      server.delivery.toCallToolResult(
        await testmail.deleteMailbox(input, context.mcpReq.signal),
        deleteContract,
      ),
  );
};
