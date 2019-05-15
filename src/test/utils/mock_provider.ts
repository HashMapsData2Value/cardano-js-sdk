import { Provider } from '../../Provider'
import { TransactionInput, TransactionOutput } from '../../Transaction'
import { Utxo } from '../../Wallet'

let mockUtxoSet: Utxo[] = []
export function seedUtxoSet (utxos: Utxo[]) {
  mockUtxoSet = utxos
}

let mockTransactionSet: { inputs: TransactionInput[], outputs: TransactionOutput[] }[] = []
export function seedTransactionSet (transactions: { inputs: TransactionInput[], outputs: TransactionOutput[] }[]) {
  mockTransactionSet = transactions
}

export function seedMockProvider (utxos: Utxo[], transactions: { inputs: TransactionInput[], outputs: TransactionOutput[] }[]) {
  mockTransactionSet = transactions
  mockUtxoSet = utxos
}

export const mockProvider: Provider = {
  submitTransaction: (_signedTransaction) => Promise.resolve(true),
  queryUtxosByAddress: (addresses) => Promise.resolve(mockUtxoSet.filter(({ address }) => addresses.includes(address))),
  queryTransactionsByAddress: (addresses) => {
    const associatedTransactions = mockTransactionSet.filter(transaction => {
      const inputsExistForAddress = transaction.inputs.filter(input => addresses.includes(input.value.address)).length > 0
      const outputsExistForAddress = transaction.outputs.filter(output => addresses.includes(output.address)).length > 0
      return inputsExistForAddress || outputsExistForAddress
    })
    return Promise.resolve(associatedTransactions)
  }
}
